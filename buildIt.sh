
mkdir tmpBuild
xcodebuild clean build CODE_SIGN_IDENTITY="-" CODE_SIGNING_REQUIRED=NO CODE_SIGNING_ALLOWED=NO ARCHS="arm64 x86_64" ONLY_ACTIVE_ARCH=NO -workspace sequel-ace.xcworkspace -scheme "Sequel Ace Release Build" -configuration Distribution
