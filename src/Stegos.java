//
// Copyright (c) 2019 Stegos AG
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

//
// Run from the root directory:
// ```bash
// cargo build --lib
// javac src/Stegos.java
// CLASSPATH="src" java -Djava.library.path=target/debug/ Stegos
// ```

class Stegos {
    private static native int init(String chain, String data_dir, String api_token, String api_endpoint);

    private static native int shutdown();

    private static native int restart();

    static {
        System.loadLibrary("stegos");
    }

    public static void main(String[] args) {
        Stegos.init("testnet", System.getProperty("user.home") + "/.local/share/stegos/testnet",
                "iUNtuwIDfPheI6BBqOin6A==", "127.0.0.1:4145");
    }
}
