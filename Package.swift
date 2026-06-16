// swift-tools-version: 5.7

import PackageDescription

let package = Package(
    name: "PreludeAuth",
    platforms: [
        .iOS(.v15),
    ],
    products: [
        .library(
            name: "PreludeAuth",
            targets: ["PreludeAuth"]
        ),
        .library(
            name: "PreludeAuthSocial",
            targets: ["PreludeAuthSocial"]
        ),
    ],
    dependencies: [
        .package(
            url: "https://github.com/prelude-so/apple-sdk.git",
            exact: "0.6.0"
        ),
    ],
    targets: [
        .target(
            name: "PreludeAuth",
            dependencies: [
                .product(name: "Prelude", package: "apple-sdk"),
            ]
        ),
        .target(
            name: "PreludeAuthSocial",
            dependencies: ["PreludeAuth"]
        ),
    ]
)
