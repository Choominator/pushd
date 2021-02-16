# Push Notifications Daemon

A daemon that intends to act as a broker between server applications that need to send push notifications to Apple devices and Apple's Push Notifications Service (APNs).  It provides asynchronous notification delivery to groups of devices and group device assignment through a simple JSON interface on a UDP socket, and uses client-side certificate-based authentication to talk to APNs on an HTTP/2 over TLS TCP connection.

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

    $ make

Which should produce the final `pushd` executable binary.

#### Build settings

The provided `Makefile` accepts some environment variables that you can pass to `make` in order to change some default values:

* `CC` - C compiler;
* `CFLAGS` - C compiler flags;
* `LDFLAGS` - Linker flags;
* `BROKERADDR` - Default local address and port to listen on;
* `DATABASEPATH` - Default path to the SQLite database file;
* `CERTPATH` - Default path to the client certificate file;
* `KEYPATH` - Default path to the private key file;

The runtime defaults can be overridden by command line flags when you run the daemon, so you don't need to change the defaults.

### Deployment

Deploying is just a matter of copying the `pushd` executable binary to a destination of your choice since there's no `make install` target yet.

## Usage

### Generating a Certificate

This daemon uses client-side certificates to authenticate with APNS.  In order to obtain a certificate for the client-side authentication you need to generate a Certificate Signing Request (CSR) along with its unencrypted private key in the Privacy Enhanced Mail (PEM) format, submit the CSR to Apple at the developer portal (paid membership required), download the signed certificate, and convert it to the PEM format.

You can generate a CSR named `pushd.csr` and its unencrypted private key named `pushd.key` in PEM format using the following command:

    $ openssl req -outform PEM -out pushd.csr -nodes -keyform PEM -keyout pushd.key -newkey rsa:2048

Then, follow the instructions at the [Establishing a Certificate-Based Connection to APNs](https://developer.apple.com/documentation/usernotifications/setting_up_a_remote_notification_server/establishing_a_certificate-based_connection_to_apns) documentation page to generate and download a signed certificate.

Finally, to convert a generated certificate named `aps_development.cer` from the Distinguished Encoding Rules (DER) format to the PEM format and save it in a file named `pushd.crt` you can use the following command:

$ openssl x509 -in aps_development.cer -inform DER -out pushd.crt -outform PEM

I might provide options to support the DER format for certificates and private keys in the future, but at the moment the Push Notifications Daemon is only accepting the PEM format.

### Running the Daemon

Running the daemon is just a matter of calling the executable binary as follows:

    $ ./pushd

If successful, the daemon will detach to the background immediately without outputting any messages, and all diagnostic messages will go to the default system logger.

### Command-Line Options

The following command line options are available:

    Usage: ./pushd [-h] [-f] [-d ARG] [-l ARG] [-s] [-p] [-c ARG] [-k ARG] [-t ARG] [-i ARG] [-r ARG]
    -h    Show help and exit
    -f    Stay in the foreground and log to standard error
    -d    Path to the database [pushd.db]
    -l    UDP address and port to listen on [localhost:7874]
    -s    Connect to host api.sandbox.push.apple.com instead of api.push.apple.com
    -p    Connect to port 2197 instead of 443
    -c    Client certificate file path [pushd.crt]
    -k    Client key file path [pushd.key]
    -t    Ping period in minutes (0 disables) [60]
    -i    Idle timeout in hours (0 disables) [24]
    -r    Rate of notifications per second per dispatch session (0 disables) [5]

the `-h` option shows the above help message and terminates, ignoring all other options.

The `-f` option prevents the daemon from detaching to the background, and logs diagnostic messages to stderr instead of the system logger.  This is useful for debugging purposes as well as for running inside a container.

The `-d` option specifies the location of the SQLite database file, which will be created and populated with tables the first time the Push Notifications Daemon is executed.  The default value for this option, if not modified at compile-time, is a file named `pushd.db` in the current working directory.

The `-l` option specifies the local host and port to bind to.  If the host resolves to more than one address, all addresses will be bound to.  The default for this option, unless modified at compile-time, is `localhost:7874`.

The `-s` option tells the Push Notifications Daemon to connect to the sandbox (development) environment instead of the production APNs environment.  This is required to test apps in development.

Specifying the `-p` option makes ``the Push Notifications Daemon connect to port 2197 instead of the traditional https 443 port.  This is useful to work around firewall rules aimed at blocking https traffic.

With the `-c` and `-k` options you can specify the paths to the client certificate and their private key files respectively.  These options are useful to allow running multiple instances of the Push Notifications Daemon, as each instance corresponds to a single app bundle identifier.  The defaults for these options, unless modified at compile-time, are `pushd.crt` and `pushd.key` respectively.

The `-t` option specifies how often, in minutes, the Push Notifications Daemon sends HTTP/2 ping frames when the connection is idle.  The default for this option is 60 minutes, which is what Apple recommends, however you may need to lower this value if you run the daemon from behind a Network Address Translation (NAT) router.  You can disable ping frames completely by setting this option to 0.

With the `-i` option you can specify how long, in hours, idle connections should last.  The Push Notifications Daemon follows a strategy that always prioritizes the latest connection when sending notifications, subject to the limits imposed either by the `-r` option (see below) or by the maximum number of concurrent HTTP/2 streams allowed by Apple, so older connections gravitate towards idleness and eventually get disconnected.  The default for this option is 24 hours, and setting it to a value of 0 makes idle connections remain active indefinitely, or at least until APNs shuts them down itself.

The `-r` option throttles the rate of notification requests per second per connection.  The default for this option is 5 notifications per second per connection.  If your average rate of notification requests in a minute exceeds this value, new connections will be open to help drain the notifications queue.  Specifying a value of 0 disables this option, which makes it possible to send as many notifications as network conditions coupled with the maximum allowed number of HTTP/2 streams allow.

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
Token:1ac599f0f90a6d178cec1f2298d51da23ab4717c7cc6896d707cdd9b90a02799

At this point you can stop the project and copy the token, which will be useful to test the daemon below.

### Testing the Daemon

To test the daemon, follow the installation instructions above and force it to run in the foreground and connect to the sandbox APNs servers as follows:

    $ ./pushd -fs

Which, if everything goes right, should display a message like the following, where 1 is the PID of the daemon and may be any other number on your system:

    pushd[1]: Push Notifications Daemon initialized successfully

To talk to the daemon we can use `nc` on another terminal as follows:

    $ nc -u localhost:7874

Nothing will happen, and no shell prompt will be displayed after this command, which is normal.

To register a device group we type the following JSON code in a single line:

    {"type": "register", "group": "Choom", "device": "1ac599f0f90a6d178cec1f2298d51da23ab4717c7cc6896d707cdd9b90a02799"}

Which should result in the following information being displayed by `pushd` on the other terminal:

    pushd[1]: Received a packet with a 117 byte request
    pushd[1]: Processed request #1 to register device 1ac599f0f90a6d178cec1f2298d51da23ab4717c7cc6896d707cdd9b90a02799 to group Choom

After registering the device token, we can now send push notifications targeting the "Choom" device group by entering the following on the `nc` terminal:

    {"type": "urgent", "expiration": 0, "group": "Choom", "key": "hello" , "payload": {"aps": {"alert": "Hello world!"}}}

Which should cause the following messages to be displayed on the `pushd` terminal:

    pushd[1]: Received a packet with a 118 byte request
    pushd[1]: Processed urgent notification request #2 to Choom group with a 32 byte payload
    pushd[1]: Creating request #2
    pushd[1]: Generating a notification queue from request #2
    pushd[1]: Creating notification #1 for request #2
    pushd[1]: Starting dispatch session #1
    pushd[1]: Starting channel #1
    pushd[1]: Resolving api.sandbox.push.apple.com
    pushd[1]: Connecting channel #1 to api.sandbox.push.apple.com [17.188.166.29] on port 443
    pushd[1]: Negotiating a TLS session on channel #1
    pushd[1]: Sending notification #1 through channel #1
    pushd[1]: Response to notification #1 request on dispatch session #1 has UUID C8EB70EE-EE50-9AAF-8407-65CFBBAF1729 and status 200
    pushd[1]: Destroying notification #1
    pushd[1]: Destroying request #2

And if everything went right, a notification should be displayed on your device.

Now you can press Control+C on both the `pushd` and `nc` terminals to force termination.

## Notes

On some systems (MacOS), the default buffer size for sockets is extremely small (2048 bytes), which is not enough to send larger notifications.  For this reason, `pushd` sets the receive buffer size on its end to 8192 bytes as part of its initialization process, however since the send buffer is equally small, your services should change it as well after creating the socket.

In order to make sure that the server `pushd` is connecting to is really Apple's, the server certificate is being verified against the local certificate authority (CA) store, which may cause it to fail if you don't have the appropriate CA certificates.  In most cases, solving this problem only requires installing a package on your system, however if your system doesn't come with the appropriate root certificates, Apple provides links to them at the [Setting Up a Remote Notification Server](https://developer.apple.com/documentation/usernotifications/setting_up_a_remote_notification_server) documentation page.
