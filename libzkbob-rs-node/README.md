# libzkbob-rs-node

This project was bootstrapped by [create-neon](https://www.npmjs.com/package/create-neon).

## Installing libzkbob-rs-node

Installing libzkbob-rs-node requires a [supported version of Node and Rust](https://github.com/neon-bindings/neon#platform-support).

You can install the project with yarn. In the project directory, run:

```sh
$ yarn install
```

This fully installs the project, including installing any dependencies and running the build.

## Building libzkbob-rs-node

If you have already installed the project and only want to run the build, run:

```sh
$ yarn build
```

This command uses the [cargo-cp-artifact](https://github.com/neon-bindings/cargo-cp-artifact) utility to run the Rust build and copy the built library into `./index.node`.

## Troubleshooting

### `librocksdb-sys` bindgen panic on macOS

On recent macOS/Xcode versions, `yarn install` or `yarn build` can fail while building `librocksdb-sys` with an error like:

```text
error: failed to run custom build command for `librocksdb-sys v6.20.3`

thread 'main' panicked at .../bindgen-0.59.2/src/ir/context.rs:
"enum_(unnamed_at_rocksdb/include/rocksdb/c_h_854_1)" is not a valid Ident
```

`libzkbob-rs-node` enables the native RocksDB backend through `libzkbob-rs`, which pulls `kvdb-rocksdb`, `rocksdb`, `librocksdb-sys`, and `bindgen`. The pinned `bindgen` version is old and can panic when used with newer Apple `libclang`.

If Homebrew LLVM 14 is installed, run the build with its `libclang`:

```sh
$ LIBCLANG_PATH=/opt/homebrew/opt/llvm@14/lib yarn install
```

For a persistent local shell setup:

```sh
$ export LIBCLANG_PATH=/opt/homebrew/opt/llvm@14/lib
$ yarn install
```

## Example
```javascript
const zp = require('libzkbob-rs-node');

const tree = new zp.MerkleTree('./treedb');
const storage = new zp.TxStorage('./txdb');

for (let i = 0; i < 100; ++i) {
    storage.add(i, Buffer.alloc(128));
    tree.addHash(i, Buffer.alloc(32));
}

const proof = tree.getProof(50);
console.log('Proof', proof);
```

## Available Scripts

In the project directory, you can run:

### `yarn install`

Installs the project, including running `yarn build`.

### `yarn build`

Builds the Node addon (`index.node`) from source.

### `yarn test`

Runs the unit tests by calling `cargo test`. You can learn more about [adding tests to your Rust code](https://doc.rust-lang.org/book/ch11-01-writing-tests.html) from the [Rust book](https://doc.rust-lang.org/book/).

## Testing suite

You can find the library usage example with few tests in `test.js` file
You can launch it with the following command after building the local library:

```sh
$ node test.js
```
