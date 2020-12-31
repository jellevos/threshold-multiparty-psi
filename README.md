# Installing dependencies on Ubuntu
## Installing GMP
- Get gmp-6.2.0.tar.lz at https://gmplib.org/
- Unpack the tar archive and enter the resulting folder
- Install m4 if necessary: `sudo apt-get install m4`
- Run `./configure`
- Run `make`
- Check if it was successful using `make check`
- Install using `sudo make install`

## Installing NTL
- Get ntl-11.4.3.tar.gz at https://www.shoup.net/ntl/download.html
- Unpack the tar archive and enter the resulting folder
- Enter src
- Run `./configure`
- Run `make`
- Check if it was successful using `make check`
- Install using `sudo make install`

# Execution
The two protocols can simply be run by compiling using `cmake` or indirectly by executing `main.cpp` from an IDE.

# Acknowledgements
_Many thanks to the initial threshold Paillier implementation from:_
https://github.com/ziyao002/Threshold-Paillier-with-ZKP
