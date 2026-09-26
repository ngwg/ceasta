#pragma once
#include <cstdint>
#include <map>
#include <memory>
#include <string>
#include <vector>

// c types you declare - structs, unions, enums, typedefs - with the layout the compiler gives
// them, so the decompiler can write p->next instead of *(long long*)(p + 8).
//
//   struct node { int value; struct node* next; };
//   typedef struct { uint16_t x, y; } point;
//
// declarations are c: comments, #pragma pack, bit fields, arrays, function pointers, nested and
// anonymous members, and the usual integer, windows and stdint type names

struct ctype_field {
    std::string name;     // "" for an anonymous struct / union member (its fields are reachable)
    std::string type;     // written out: "int", "struct node*", "char[16]", "void (*)(int)"
    uint32_t offset = 0;
    uint32_t size = 0;
    bool bitfield = false; // bits wide (0: an unnamed "int : 0" that only aligns what follows)
    uint8_t bit_offset = 0, bits = 0;
    bool operator==(const ctype_field& o) const
    {
        return name == o.name && type == o.type && offset == o.offset && size == o.size && bitfield == o.bitfield &&
               bit_offset == o.bit_offset && bits == o.bits;
    }
};

struct ctype_def {
    enum class kind : uint8_t { struct_, union_, enum_, typedef_ } k = kind::struct_;
    std::string name;
    uint32_t size = 0, align = 1;
    std::vector<ctype_field> fields;                      // struct / union
    std::vector<std::pair<std::string, int64_t>> values;  // enum
    std::string target;                                   // typedef: the type it names
    uint32_t pack = 0;                                    // #pragma pack in force, 0: none
    bool packed = false;                                  // __attribute__((packed))
    uint32_t aligned = 0;                                 // __attribute__((aligned(n))), alignas(n)
    bool incomplete = false;                              // only declared (struct x;): pointers to it work
    bool operator==(const ctype_def& o) const
    {
        return k == o.k && name == o.name && size == o.size && align == o.align && fields == o.fields &&
               values == o.values && target == o.target && pack == o.pack && packed == o.packed &&
               aligned == o.aligned && incomplete == o.incomplete;
    }
    bool operator!=(const ctype_def& o) const { return !(*this == o); }
};

struct ctype_node; // a parsed type (ctypes.cpp)

class ctypes {
public:
    // pointers of ptr_size bytes; windows: long is 4 bytes, wchar_t 2, msvc's bit fields.
    // arm64 linux: a zero-width bit field aligns the struct too; apple arm64 and windows: long
    // double is a double
    void set_abi(int ptr_size, bool windows, bool arm64 = false, bool apple = false);

    // parses c declarations and adds what they define, replacing a definition of the same
    // name. false (and nothing added) on an error; err says what and where. lenient (a header
    // from somewhere else): what it can't read is skipped, and err says how much
    bool add(const std::string& text, std::string& err, std::vector<std::string>* names = nullptr,
             bool lenient = false);
    bool remove(const std::string& name);
    void clear();
    bool empty() const { return defs_.empty(); }

    // "node", "struct node", "union u", a typedef's name
    const ctype_def* find(const std::string& name) const;
    // size and alignment of a type written in c ("int", "struct node*", "point[4]"); false when
    // it names something unknown
    bool layout(const std::string& type, uint32_t& size, uint32_t& align) const;
    // the struct / union a pointer type points to ("struct node*", "node *", a typedef of one)
    const ctype_def* pointee(const std::string& type) const;
    // the struct / union a type is (not a pointer to one)
    const ctype_def* aggregate(const std::string& type) const;
    // for a pointer to a scalar ("int*", "char *"): the size of what it points to, else 0
    uint32_t scalar_pointee(const std::string& type) const;
    // the name a type is made of ("struct node" for "struct node*[4]", "DWORD"), and whether
    // that's behind a pointer; "" when it doesn't parse
    std::string base_of(const std::string& type, bool& pointer) const;
    // what a read of width bytes (0: any) at offset off inside s is: ".hdr.len" -> path
    // "hdr.len" and its type. with index (not empty) the offset is the start of an array
    // element: path "items[<index>]"
    bool member_at(const ctype_def& s, uint64_t off, int width, std::string& path, std::string& type,
                   const std::string& index = std::string(), uint32_t scale = 0) const;

    // c text: one definition, normalized, the offsets as comments; all of them in the order
    // they depend on each other (what the project file keeps)
    std::string text(const ctype_def& d, bool offsets = true) const;
    std::string all_text(bool offsets = false) const;
    // all_text, one per definition; names gets the name each one is of
    std::vector<std::string> texts(bool offsets = false, std::vector<std::string>* names = nullptr) const;
    // the names in the order texts() writes them, without writing them
    std::vector<std::string> order() const;
    // the names, in definition order
    const std::vector<std::string>& names() const { return order_; }

    // the type without const / volatile and extra spaces: "const  char *" -> "char*"
    static std::string normalize(const std::string& type);

private:
    friend struct ctype_parser;
    using node = std::shared_ptr<const ctype_node>;
    std::map<std::string, ctype_def> defs_;
    std::vector<std::string> order_;
    int ptr_ = 8;
    bool win_ = false, aapcs_ = false, short_ld_ = false;
    int anon_ = 0;                                 // names for anonymous structs: __anon_<n>
    mutable std::map<std::string, node> cache_;    // type text -> its tree
    bool scalar(const std::string& word, uint32_t& size) const;
    node parse_type(const std::string& text, std::string& err) const;
    bool layout_node(const node& t, uint32_t& size, uint32_t& align, std::string& err, int depth = 0) const;
    node strip(node t) const; // through typedefs
    void write_fields(const ctype_def& d, std::string& s, int indent, bool offsets, uint32_t base) const;
    std::vector<std::string> texts(bool offsets, std::vector<std::string>* names, bool names_only) const;
    std::string decl_text(const node& t, const std::string& name, int indent, bool offsets, uint32_t base) const;
};
