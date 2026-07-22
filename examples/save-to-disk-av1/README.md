# save-to-disk-av1

save-to-disk-av1 is a simple application that shows how to save a video to disk using AV1.

## Instructions

### Open save-to-disk-av1 example page

[jsfiddle.net](https://jsfiddle.net/8jv91r25/) you should see your Webcam, two text-areas and two buttons:
`Copy browser SDP to clipboard`, `Start Session`.

### Run save-to-disk-av1, with your browsers SessionDescription as stdin

In the jsfiddle the top textarea is your browser's Session Description. Press `Copy browser SDP to clipboard` or copy
the base64 string manually.
We will use this value in the next step.

#### Linux/macOS

Run `echo $BROWSER_SDP | cargo run --example save-to-disk-av1`

#### Windows

1. Paste the SessionDescription into a file.
1. Run `cargo run --example save-to-disk-av1 < my_file`

### Input save-to-disk-av1's SessionDescription into your browser

Copy the text that `save-to-disk-av1` just emitted and copy into second text area

### Hit 'Start Session' in jsfiddle, wait, close jsfiddle, enjoy your video!

In the folder you ran `save-to-disk-av1` you should now have a file `output.ivf` play with your video player of choice!

Congrats, you have used WebRTC.rs!
