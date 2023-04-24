# share-anywhere

Sharing the clipboard data between OSX and Linux

Use [vue3](https://vuejs.org/) + [element-plus](https://element-plus.gitee.io/) + [tauri](https://tauri.app/)

## Features

- [x] Plain Text
- [x] Image
- [ ] File

## Installation

### Prerequisites

`rust 1.68` + `npm v18.15` , See [Tauri Prerequisites](https://tauri.app/v1/guides/getting-started/prerequisites)

### Build

```shell
git clone git@github.com:stan-chen/share-anywhere.git
cd share-anywhere
## nvm use
# install nodejs dep
npm install --no-save
# install tauri cli
cargo install tauri-cli --version ^1
npm run tauri:build
```

## Impl Overview

Use UDP multicast to publish clipboard summary (AES-GCM key encryption can be configured), 
and the receiver determines whether to update the clipboard by comparing it with the local clipboard data.

Update the clipboard using HTTP(s) API (client & server certificate authentication can be configured).

## Limit

* Due to the temporary inability to obtain the clipboard timestamp, the update adopts a priority release strategy (whoever publishes last will be applied).
* File sharing is relatively complex, so it is currently not supported.
