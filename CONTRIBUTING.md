# CONTRIBUTING

Find an area you can help with and do it. Open source is about collaboration
and open participation. Try to make your code look like what already exists
and submit a pull request.

The [list of issues](https://github.com/stegos/stegos/issues) is a good place
to start, especially the ones tagged as "help wanted" (but don't let that
stop you from looking at others). If you're looking for additional ideas,
the code includes `TODO` comments for minor to major improvements.
Grep is your friend.

Additional tests are rewarded with an immense amount of positive karma.

More documentation or updates/fixes to existing documentation are also very
welcome. However, if submitting a PR(Pull-Request) consisting of documentation
changes only, please try to ensure that the change is significantly more
substantial than one or two lines. For example, working through an install
document and making changes and updates throughout as you find issues is
worth a PR. For typos and other small changes, either contact one of
the developers, or if you think it's a significant enough error to cause
problems for other users, please feel free to open an issue.

## Find Us

If any help is needed during your effort to contribute on this project,
please don't hesitate to contact us:
* [Telegram chat](https://t.me/stegos4privacy)

## Install rustfmt

You should use rustup:.

```
rustup component add rustfmt
rustup update
rustfmt --version
```

Verify you did get version `rustfmt 1.0.0-stable (4a4e508 2018-11-29)`
or newer.

## Running rustfmt manually

You can run rustfmt (i.e. rustfmt-preview) on one file or on all files.

For example:

```
rustfmt client.rs
```

You can also re-format entirely project by running `cargo fmt`:

```
cargo fmt
```

**Notes**:
1. *Please add the rustfmt corrections as a separate commit at the end of your
   Pull Request to make the reviewers happy.*

2. *If you're still not sure about what should do on the format, please feel
   free to ignore it. Since `rustfmt` is just a tool to make your code having
   pretty formatting, your changed code is definitely more important than
   the format. Hope you're happy to contribute on this open source project!*

3. And anyway please don't use ~~`cargo +nightly fmt`~~ if at all possible.


## Install cargo audit

In order to keep our dependencies secure,
we using cargo audit as part of our CI.

To install cargo audit use cargo install:

```
cargo install cargo-audit
cargo audit --version
```

Verify that you using latest cargo-audit, it should be version `cargo-audit 0.6.1`
or newer.

## Using cargo audit

Using cargo audit is simple. Just run:

```
cargo audit
```

And checks that it reports

```
Success No vulnerable packages found
```

If cargo audit found any vulnerable crate, it would be good to
update crate version.

## Thanks for any contribution

Even one word correction are welcome! Our objective is to encourage you to
get interested in Stegos and contribute in any way possible.

Thanks for any help!
