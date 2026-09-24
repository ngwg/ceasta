#pragma once
// test helper: rasterizes imgui draw data in software and writes a .ppm image, so the ui
// can be looked at on machines without a gpu or a window (ci, containers).
#include "imgui.h"
#include <algorithm>
#include <cmath>
#include <cstdio>
#include <string>
#include <vector>

namespace snapshot {

inline bool save(const ImDrawData* dd, const std::string& path)
{
    int w = (int)dd->DisplaySize.x, h = (int)dd->DisplaySize.y;
    if (w <= 0 || h <= 0)
        return false;
    std::vector<float> fb((size_t)w * h * 3, 0.07f);
    for (int li = 0; li < dd->CmdListsCount; li++) {
        const ImDrawList* dl = dd->CmdLists[li];
        for (const ImDrawCmd& cmd : dl->CmdBuffer) {
            if (cmd.UserCallback)
                continue;
            const ImTextureData* tex = cmd.TexRef._TexData;
            int cx0 = std::max(0, (int)(cmd.ClipRect.x - dd->DisplayPos.x));
            int cy0 = std::max(0, (int)(cmd.ClipRect.y - dd->DisplayPos.y));
            int cx1 = std::min(w, (int)std::ceil(cmd.ClipRect.z - dd->DisplayPos.x));
            int cy1 = std::min(h, (int)std::ceil(cmd.ClipRect.w - dd->DisplayPos.y));
            for (unsigned int i = 0; i + 2 < cmd.ElemCount; i += 3) {
                const ImDrawVert* v[3];
                for (int k = 0; k < 3; k++)
                    v[k] = &dl->VtxBuffer[(int)(cmd.VtxOffset + dl->IdxBuffer[(int)(cmd.IdxOffset + i + k)])];
                double x0 = v[0]->pos.x - dd->DisplayPos.x, y0 = v[0]->pos.y - dd->DisplayPos.y;
                double x1 = v[1]->pos.x - dd->DisplayPos.x, y1 = v[1]->pos.y - dd->DisplayPos.y;
                double x2 = v[2]->pos.x - dd->DisplayPos.x, y2 = v[2]->pos.y - dd->DisplayPos.y;
                double area = (x1 - x0) * (y2 - y0) - (x2 - x0) * (y1 - y0);
                if (std::fabs(area) < 1e-9)
                    continue;
                if (area < 0) { // make it counter clockwise in screen space
                    std::swap(x1, x2);
                    std::swap(y1, y2);
                    std::swap(v[1], v[2]);
                    area = -area;
                }
                // top-left rule: pixels exactly on a shared edge belong to one triangle only
                auto top_left = [](double ax, double ay, double bx, double by) {
                    return (ay == by && bx < ax) || (by > ay);
                };
                bool tl0 = top_left(x1, y1, x2, y2), tl1 = top_left(x2, y2, x0, y0), tl2 = top_left(x0, y0, x1, y1);
                int bx0 = std::max(cx0, (int)std::floor(std::min({x0, x1, x2})));
                int by0 = std::max(cy0, (int)std::floor(std::min({y0, y1, y2})));
                int bx1 = std::min(cx1, (int)std::ceil(std::max({x0, x1, x2})));
                int by1 = std::min(cy1, (int)std::ceil(std::max({y0, y1, y2})));
                for (int py = by0; py < by1; py++)
                    for (int px = bx0; px < bx1; px++) {
                        double sx = px + 0.5, sy = py + 0.5;
                        double e0 = (x2 - x1) * (sy - y1) - (y2 - y1) * (sx - x1);
                        double e1 = (x0 - x2) * (sy - y2) - (y0 - y2) * (sx - x2);
                        double e2 = (x1 - x0) * (sy - y0) - (y1 - y0) * (sx - x0);
                        if (e0 < 0 || e1 < 0 || e2 < 0 || (e0 == 0 && !tl0) || (e1 == 0 && !tl1) || (e2 == 0 && !tl2))
                            continue;
                        float w0 = (float)(e0 / area), w1 = (float)(e1 / area), w2 = (float)(e2 / area);
                        float col[4];
                        for (int c = 0; c < 4; c++) {
                            float a = ((v[0]->col >> (8 * c)) & 0xff) / 255.0f;
                            float b = ((v[1]->col >> (8 * c)) & 0xff) / 255.0f;
                            float d = ((v[2]->col >> (8 * c)) & 0xff) / 255.0f;
                            col[c] = a * w0 + b * w1 + d * w2;
                        }
                        if (tex && tex->Pixels) {
                            float u = v[0]->uv.x * w0 + v[1]->uv.x * w1 + v[2]->uv.x * w2;
                            float t = v[0]->uv.y * w0 + v[1]->uv.y * w1 + v[2]->uv.y * w2;
                            int tx = std::min(tex->Width - 1, std::max(0, (int)(u * tex->Width)));
                            int ty = std::min(tex->Height - 1, std::max(0, (int)(t * tex->Height)));
                            const unsigned char* p = tex->Pixels + ((size_t)ty * tex->Width + tx) * tex->BytesPerPixel;
                            if (tex->BytesPerPixel == 4) {
                                for (int c = 0; c < 4; c++)
                                    col[c] *= p[c] / 255.0f;
                            } else {
                                col[3] *= p[0] / 255.0f;
                            }
                        }
                        float* dst = &fb[((size_t)py * w + px) * 3];
                        for (int c = 0; c < 3; c++)
                            dst[c] = dst[c] * (1.0f - col[3]) + col[c] * col[3];
                    }
            }
        }
    }
    FILE* f = fopen(path.c_str(), "wb");
    if (!f)
        return false;
    fprintf(f, "P6\n%d %d\n255\n", w, h);
    std::vector<unsigned char> row((size_t)w * 3);
    for (int y = 0; y < h; y++) {
        for (int x = 0; x < w * 3; x++)
            row[(size_t)x] = (unsigned char)std::min(255.0f, std::max(0.0f, fb[(size_t)y * w * 3 + x] * 255.0f + 0.5f));
        fwrite(row.data(), 1, row.size(), f);
    }
    fclose(f);
    return true;
}

}
