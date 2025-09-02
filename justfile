bindir := "build"
generator := "Ninja"
cxx := "clang++"

build:
    cmake -G '{{generator}}' -S . -B '{{bindir}}' \
        -DCMAKE_EXPORT_COMPILE_COMMANDS=ON \
        -DCMAKE_CXX_COMPILER='{{cxx}}' \
        -DCMAKE_BUILD_TYPE=Release \
        -DVANISSH_ENABLE_NATIVE=ON \
        -DVANISSH_ENABLE_FAST_MATH=ON
    cmake --build '{{bindir}}' --config Release --parallel
