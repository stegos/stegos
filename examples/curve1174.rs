// Test Fast Implementation of Edwards Curve Curve1174
// DM/Emotiq 08/18
/* -------------------------------------------------------------------------
The MIT License

Copyright (c) 2018 Emotiq AG

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
----------------------------------------------------------------------------
Internally, ECC point multiplication depends on projective coordinates expressed 
as 4 components (x, y, z, t), each of which is expressed as 51-bit integer fragments 
of a 256 bit number. This permits very fast addition/subtraction of field elements, 
with overflows spilling into the upper bits of each 64-bit fragment. During multiply 
operations these overflows are reapportioned to higher fragments.

Externally the field elements of the coordinates are held as 256 bit bignums in 
little-endian order, normally expressed as quads of 64-bit unsigned fragments. When 
necessary, these are forcibly viewed through an "unsafe" transformation to/from 32-bytes.

---------------------------------------------------------------------------- */
extern crate stegos_crypto;

use stegos_crypto::curve1174::*;

// -------------------------------------------------------------------------------
fn main() {
    curve1174_tests();
}
