#pragma once

// "ceasta-cli mcp <file> [options]": serve the file to an ai client over the model context
// protocol. argv/argc are the arguments after "mcp".
int cmd_mcp(int argc, char** argv);
