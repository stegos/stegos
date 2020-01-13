#!/bin/bash
#
# CI tool
#

API_V4_PATH="https://gitlab.aws.stegos.com/api/v4"
STEGOS_PROJECT_ID="Stegos%2Fstegos"
CURRENT_COMMIT=$(git log -n1 --pretty='%h')
BRANCH_OR_TAG=$(git describe --exact-match --tags HEAD || echo $CURRENT_COMMIT)

STEGOS_LINUX="release/stegos-linux-x64\?job\=release:linux-x64"
STEGOSD_LINUX="release/stegos-linux-x64\?job\=release:linux-x64"

STEGOS_MACOS="release/stegos-macos-x64\?job\=release:macos-x64"
STEGOSD_MACOS="release/stegos-macos-x64\?job\=release:macos-x64"

STEGOSD_WIN="release/stegosd-win-x64.zip\?job\=release:win-x64"
STEGOS_WIN="release/stegos-win-x64.zip\?job\=release:win-x64"

mkdir -p release/$BRANCH_OR_TAG

echo "Using ref $BRANCH_OR_TAG"

for os in macos linux win
do
   OS=${os}
    for file in stegos stegosd 
    do 
      FILE=${file}-${os}-x64

      if [[ ${os} == win ]]; then 
        FILE=$FILE.zip
        OS="windows"
      fi
      echo "Loading ${file} for ${os}."
      curl "$API_V4_PATH/projects/$STEGOS_PROJECT_ID/jobs/artifacts/$BRANCH_OR_TAG/raw/release/$FILE?job=release:$OS-x64" --output release/$BRANCH_OR_TAG/$FILE -#
      
      filetype=$(file release/$BRANCH_OR_TAG/$FILE | cut -d\  -f2);
      if [[ ${filetype} = "JSON" ]]; then 
        echo "Server returns:";
        cat release/$BRANCH_OR_TAG/$FILE;
        rm release/$BRANCH_OR_TAG/$FILE;
        exit 1
      fi
    done
done


echo "Generating SHA256SUM."
sha256sum release/$BRANCH_OR_TAG/* > release/$BRANCH_OR_TAG/SHA256SUM
echo "Signing using gpg"
gpg --sign release/$BRANCH_OR_TAG/SHA256SUM
