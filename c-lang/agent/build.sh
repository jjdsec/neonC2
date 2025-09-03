gcc src/*.c -o dist/agent -lpthread -lm -Wall -Wextra -Werror -Iinclude
# This script compiles the agent source files into an executable named 'agent' in the 'dist' directory.
# It uses the pthread and math libraries, and includes the 'include' directory for header files.
# The compilation will show all warnings and treat them as errors.
