# Push Notifications Daemon

A daemon that intends to act as a broker between server applications that need to send push notifications to Apple devices and Apple's Push Notifications Service (APNs).  It provides asynchronous notification delivery to groups of devices and group device assignment through a simple JSON interface on two UDP sockets, and uses client-side certificate-based authentication to talk to APNs on an HTTP/2 over TLS TCP connection.

This project is still in an early stage of development and thus must not be used in production since it hasn't been properly tested yet.

## Installation

### Dependencies

This project has the following dependencies:

* [libevent](https://libevent.org) (tested with version 2.1.12);
* [yajl](https://lloyd.github.io/yajl/) (tested with version 2.1.0);
* [sqlite](https://www.sqlite.org/index.html) (tested with version 3.34.1);
* [OpenSSL](https://www.openssl.org); (tested with version 1.1.1i);
* [Nghttp2](https://nghttp2.org) (tested with version 1.42.0).

### Compilation

After installing the development packages for the aforementioned dependencies, clone this repository with:

    $ git clone https://github.com/Choominator/pushd.git

Followed by building the project with:

    $ cd pushd
    $ make

Which should produce the final `pushd` executable binary.

#### Build settings

The provided `Makefile` accepts some environment variables that you can pass to `make` in order to change some default values:

* `CC` - C compiler;
* `CFLAGS` - C compiler flags;
* `LDFLAGS` - Linker flags;
* `DATABASEPATH` - Default path to the SQLite database file;
* `CERTPATH` - Default path to the client certificate file;
* `KEYPATH` - Default path to the private key file;
* `LOGPATH` - Default path to the log file.

The runtime defaults can be overridden by command line flags when you run the daemon, so you don't need to change the defaults.

### Deployment

Deploying is just a matter of copying the `pushd` executable binary to a destination of your choice since there's no `make install` target yet.

## Usage

### Generating a Certificate

This daemon uses client-side certificates to authenticate with APNs.  In order to obtain a certificate for the client-side authentication you need to generate a Certificate Signing Request (CSR) along with its unencrypted private key in the Privacy Enhanced Mail (PEM) format, submit the CSR to Apple at the developer portal (paid membership required), download the signed certificate, and convert it to the PEM format.

You can generate a CSR named `pushd.csr` and its unencrypted private key named `pushd.key` in PEM format using the following command:

    $ openssl req -outform PEM -out pushd.csr -nodes -keyform PEM -keyout pushd.key -newkey rsa:2048

Then, follow the instructions at the [Establishing a Certificate-Based Connection to APNs](https://developer.apple.com/documentation/usernotifications/setting_up_a_remote_notification_server/establishing_a_certificate-based_connection_to_apns) documentation page to generate and download a signed certificate.

Finally, to convert a generated certificate named `aps_development.cer` from the Distinguished Encoding Rules (DER) format to the PEM format and save it in a file named `pushd.crt` you can use the following command:

$ openssl x509 -in aps_development.cer -inform DER -out pushd.crt -outform PEM

I might provide options to support the DER format for certificates and private keys in the future, but at the moment the Push Notifications Daemon is only accepting the PEM format.

### Running the Daemon

Running the daemon is just a matter of calling the executable binary as follows:

    $ ./pushd

If successful, the daemon will detach to the background immediately without outputting any messages, and all diagnostic messages will go to the specified log file.

### Command-Line Options

The following command line options are available:

    Usage: ./pushd [-h] [-f] [-d ARG] [-l ARG] [-g ARG] [-n ARG] [-s] [-p] [-c ARG] [-k ARG] [-t ARG] [-i ARG] [-r ARG] [-o ARG]
    -h    Show help and exit
    -f    Stay in the foreground and log to standard error
    -d    Path to the database [pushd.db]
    -l    Local address to listen on [localhost]
    -g    Group device registration UDP port [7734]
    -n    Notification request UDP port [7874]
    -s    Connect to host api.sandbox.push.apple.com instead of api.push.apple.com
    -p    Connect to port 2197 instead of 443
    -c    Client certificate file path [pushd.crt]
    -k    Client key file path [pushd.key]
    -t    Ping period in minutes (0 disables) [60]
    -i    Idle timeout in hours (0 disables) [24]
    -r    Rate of notifications per second per dispatch session (0 disables) [5]
    -o    Log file path [pushd.log]

the `-h` option shows the above help message and terminates, ignoring all other options.

The `-f` option prevents the daemon from detaching to the background, and logs diagnostic messages to stderr instead of the system logger.  This is useful for debugging purposes as well as for running inside a container.

The `-d` option specifies the location of the SQLite database file, which will be created and populated with tables the first time the Push Notifications Daemon is executed.  The default value for this option, if not modified at compile-time, is a file named `pushd.db` in the current working directory.

The `-l`, `-g`, and `-n` options specify the local host and UDP ports to bind to for registration and notification requests respectively.  If the host resolves to more than one address, all addresses will be bound to.  The default for these options, is `localhost` for `-l`, `7734` for `-g`, and `7874` for `-n`.

The `-s` option tells the Push Notifications Daemon to connect to the sandbox (development) environment instead of the production APNs environment.  This is required to test apps in development.

Specifying the `-p` option makes ``the Push Notifications Daemon connect to port 2197 instead of the traditional https 443 port.  This is useful to work around firewall rules aimed at blocking https traffic.

With the `-c` and `-k` options you can specify the paths to the client certificate and its private key files respectively.  These options are useful to allow running multiple instances of the Push Notifications Daemon, as each instance corresponds to a single app bundle identifier.  The defaults for these options, unless modified at compile-time, are `pushd.crt` and `pushd.key` respectively in the current working directory.

The `-t` option specifies how often, in minutes, the Push Notifications Daemon sends HTTP/2 ping frames when the connection is idle.  The default for this option is 60 minutes, which is what Apple recommends, however you may need to lower this value if you run the daemon from behind a Network Address Translation (NAT) router.  You can disable ping frames completely by setting this option to 0.

With the `-i` option you can specify how long, in hours, idle connections should last.  The Push Notifications Daemon follows a strategy that always prioritizes the latest connection when sending notifications, subject to the limits imposed either by the `-r` option (see below) or by the maximum number of concurrent HTTP/2 streams allowed by Apple, so older connections gravitate towards idleness and eventually get disconnected.  The default for this option is 24 hours, and setting it to a value of 0 makes idle connections remain active indefinitely, or at least until APNs shuts them down itself.

The `-r` option throttles the rate of notification requests per second per connection.  The default for this option is 5 notifications per second per connection.  If your average rate of notification requests in a minute exceeds this value, new connections will be open to help drain the notifications queue.  Specifying a value of 0 disables this option, which makes it possible to send as many notifications as network conditions coupled with the maximum allowed number of HTTP/2 streams allow.

the `-o` option sets the file to which log messages are appended.  The default for this option,  unless modified at compile-time, is a file named `pushd.log` in the current working directory.

### Communicating With the Daemon

This daemon accepts input in the form of UDP packets containing complete JSON strings sent to its listening ports.  The root object for both the group registration and notification request ports is always a dictionary.

The dictionary for the group registration port accepts the following keys:

* `device` - A mandatory key whose value must be a string containing the lower-case hexadecimal representation of the device token to assign.
* `group` - A mandatory key whose value must be a string containing the name of the group to register or modify;

The dictionary sent to the notification request port accepts the following keys:

* `groups` - A mandatory key whose value must be an array of strings containing the names of the device groups to notify.  This causes `pushd` to generate only one notification per device even if a device is registered to more than one of the specified groups.
* `type` - An optional key whose value must be the string `"background"`, `"normal"`, or `"urgent"`, for background notifications, normal alerts, or urgent alerts respectively.  The default value if this key is not specified is `"background"`.
* `expiration` - An optional key whose value must be an integer containing the Unix time, that is, the number of seconds elapsed since 1970-01-01 00:00:00 Coordinated Universal Time until which APNs should attempt to deliver the notifications, or `0` to only attempt to deliver them once.  The default value if this key is not specified is `0`.
* `key` - An optional key whose value must be a string of at most 64 bytes identifying the notification.  All notifications with the same value for this key will coalesce into a single alert.
* `payload` - A mandatory key whose value must be a dictionary structured as specified by Apple at the [Generating a Remote Notification](https://developer.apple.com/documentation/usernotifications/setting_up_a_remote_notification_server/generating_a_remote_notification) documentation page.

## Example

### Test Project

To test the Push Notifications Daemon, create a SwiftUI project using the SwiftUI lifecycle in Xcode, name it 'Push", and replace the contents of `PushApp.swift` with the following code:

```swift
import SwiftUI
import UserNotifications

@main struct PushApp: App {
    @UIApplicationDelegateAdaptor private var adaptor: Delegate

    var body: some Scene {
        WindowGroup {
            Text("Hello world!")
        }
    }

    private final class Delegate: NSObject, UIApplicationDelegate {
        func application(_ application: UIApplication, didFinishLaunchingWithOptions _: [UIApplication.LaunchOptionsKey : Any]? = nil) -> Bool {
            UNUserNotificationCenter.current().requestAuthorization(options: [.alert], completionHandler: {(authorized, _) in print("Authorized:", authorized)})
            print("Registering")
            application.registerForRemoteNotifications()
            return true
        }

        func application(_: UIApplication, didRegisterForRemoteNotificationsWithDeviceToken token: Data) {
            print("Success!")
            print("Token:\(token.reduce("", {$0 + String(format: "%02x", $1)}))")
        }

        func application(_ application: UIApplication, didFailToRegisterForRemoteNotificationsWithError error: Error) {
            print("Failure")
        }
    }
}
```

Then go to the project editor, click on Signing & Capabilities, click on the plus button, and add the Push Notifications Capability, which will make Xcode add an entitlements file with the aps-environment entitlement to the project.

Now connect an actual device to your computer, select your device in Xcode's Product menu, run the code, which should make Xcode register a bundle identifier with the required capabilities on your developer account, and allow the app to display notifications when prompted.

Once you have allowed the app to display push notifications you should have something like the following on the debug console:

    Registering
    Authorized: true
    Success!
    Token:be6406fe9e686c11f999c9d47e33b41be56be48f0c77570423bb89f5b51cf127

At this point you can stop the project and copy the token, which will be useful to test the daemon below.

### Testing the Daemon

To test the daemon, follow the usage instructions above to generate a signed certificate and private key and force it to run in the foreground and connect to the sandbox APNs servers as follows:

    $ ./pushd -fs

Which, if everything goes right, should display a message like this, where 1 is the PID of the daemon and may be any other number on your system:

    Info: Push Notifications Daemon initialized successfully

Before sending notifications, the target device token that you copied from the debug console after running the test project must be added to the daemon.  To do so you must send a UDP packet instructing the daemon to do just that to its registration port.  One way to do that is by using `netcat`, or `nc` for short, on another terminal as follows:

    $ nc -u localhost 7734

And then entering the following JSON code:

    {"device": "be6406fe9e686c11f999c9d47e33b41be56be48f0c77570423bb89f5b51cf127", "group": "Choom"}

Which should result in the following additional log messages being displayed by `pushd` on its terminal:

    Debug: Received a 97 byte packet on a registration socket
    Info: Processed a registration request to assign the device token be6406fe9e686c11f999c9d47e33b41be56be48f0c77570423bb89f5b51cf127 to group Choom

After registering the device token, you will be ready to send push notifications to the registered device group.

To send a notification you must first switch to the notification request port, so press Control+C on the `nc` terminal to return to the shell and enter the following command:

    $ nc -u localhost 7874

Followed by entering the following JSON code:

    {"groups": ["Choom"], "type": "urgent", "payload": {"aps": {"alert": "Hello world!"}}}

Which should cause the following messages to be displayed on the `pushd` terminal:

    Debug: Received a 103 byte packet on a request socket
    Debug: Generated 1 notifications from request #1
    Debug: Created channel #1
    Debug: Resolving api.sandbox.push.apple.com
    Debug: Resolved api.sandbox.push.apple.com
    Debug: Connecting to 17.188.166.29 port 443 on channel #1
    Debug: Connection established on channel #1
    Debug: Sending notification #1 through channel #1
    Info: Response to notification #1 request on dispatch session #1 has UUID 375B7575-0AF4-0505-CFA7-BCD5530334D7 and status 200
    Debug: Freed resources from request #1
    Debug: Destroyed notification #1

And if everything goes right, a notification should be displayed on your device.

Now you can press Control+C on both the `pushd` and `nc` terminals to force termination.

## Notes

On some systems (MacOS), the default buffer size for sockets is quite small (2048 bytes), which is not enough to send larger notifications.  For this reason, `pushd` sets the receive buffer size on its end to 8192 bytes as part of its initialization process, however since the send buffer is equally small, your services should change it as well after creating the socket to talk to `pushd`.

In order to make sure that the server `pushd` is connecting to is really Apple's, the server certificate is being verified against the local certificate authority (CA) store, which may cause it to fail if you don't have the appropriate root certificates installed.  In most cases, solving this problem only requires installing a package on your system, however if your system doesn't come with the appropriate root certificates, Apple provides links to them at the [Setting Up a Remote Notification Server](https://developer.apple.com/documentation/usernotifications/setting_up_a_remote_notification_server) documentation page.

## Future Plans

The following is a list of changes that I intend to make in the future:

* Add support for all the notification types specified at the [Sending Notification Requests to APNs](https://developer.apple.com/documentation/usernotifications/setting_up_a_remote_notification_server/sending_notification_requests_to_apns) documentation page;
* Make a single instance of the daemon able to handle multiple client-side certificates.
* Add support for token-based authentication;
* Replace most of the command-line options with settings in a configuration file;
