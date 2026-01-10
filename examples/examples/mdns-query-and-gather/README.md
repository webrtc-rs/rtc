# mdns-query-and-gather

mdns-query-and-gather is a WebRTC.rs application that shows how you can hide local ip with mDNS.

## Instructions

### Build mdns-query-and-gather

```shell
cargo build --example mdns-query-and-gather
```

### Open mdns-query-and-gather example page

[jsfiddle.net](https://jsfiddle.net/e41tgovp/)

### Run mdns-query-and-gather, with your browsers SessionDescription as stdin

In the jsfiddle the top textarea is your browser's session description, copy that and:

#### Linux/macOS

Run `echo $BROWSER_SDP | ./target/debug/examples/mdns-query-and-gather`

#### Windows

1. Paste the SessionDescription into a file.
1. Run `./target/debug/examples/mdns-query-and-gather < my_file`

### Input mdns-query-and-gather's SessionDescription into your browser

Copy the text that `mdns-query-and-gather` just emitted and copy into second text area

### Hit 'Start Session' in jsfiddle

Under Start Session you should see 'Checking' as it starts connecting. If everything worked you should see
`New DataChannel foo 1`

Now you can put whatever you want in the `Message` textarea, and when you hit `Send Message` it should appear in your
terminal!

WebRTC.rs will send random messages every 5 seconds that will appear in your browser.

Congrats, you have used WebRTC.rs!
