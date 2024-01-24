git clone --depth=1 https://github.com/open-quantum-safe/liboqs
cmake -S liboqs -B liboqs/build -DBUILD_SHARED_LIBS=ON
cmake --build liboqs/build --parallel 8
cmake --build liboqs/build --target install


## DYLD_LIBRARY_PATH is macos
#export DYLD_LIBRARY_PATH=$DYLD_LIBRARY_PATH:/usr/local/lib

## On Linux
export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/usr/local/lib

## On Windows
#set PATH=%PATH%;C:\Program Files (x86)\liboqs\bin


python3 -mvenv env 
source env/bin/activate
python3 -m ensurepip --upgrade


git clone --depth=1 https://github.com/open-quantum-safe/liboqs-python
cd liboqs-python
pip install .

