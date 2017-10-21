# binja_sibyl

A Miasm2 + binaryninja based function divination.

## What it does

[Sybil](https://github.com/cea-sec/Sibyl) is a tool to recognize standard functions based on their side effects.
For a detailed introduction see [Sybil's README](https://github.com/cea-sec/Sibyl/blob/master/README.md).

## Screenshot

![Screenshot](https://user-images.githubusercontent.com/1985669/31853411-16df2d64-b688-11e7-91be-fc5ac8d08ab5.png)

## Options

- `Function prefix`: a prefix to prepend to the function name after it has been recognized (e.g.: `prefix_strlen`).
- `Function selector`: whether to apply the analysis to unknown functions (starting with `sub_`) or every funtion.
- `Add comment`: whether to add a comment at the top of the function. Useful to keep in mind that the function name might be wrong (Sibyl can give false positives).

## Speed

Currently, binja_sibyl uses a single thread so, as of now, it's slower than running Sibyl manually.

## Props

Shout out to Camille MOUGEY, the author os Sibyl.
The underlying is pretty clever.
