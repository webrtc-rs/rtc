# play-from-disk-playlist-control

Streams Opus pages from multi or single track Ogg containers, exposes the playlist over an SCTP DataChannel, and lets
the browser hop between tracks while showing artist/title metadata parsed from OpusTags.

## What this showcases

- Reads multi-stream Ogg containers with `OggReader` and keeps per-serial playback state.
- Publishes playlist + now-playing metadata (artist/title/vendor/comments) over a DataChannel.
- Browser can send `next`, `prev`, or a 1-based track number to jump around.
- Audio is sent as Opus over RTP, metadata/control ride over SCTP.

## Prepare a demo playlist

By default, the example looks for `playlist.ogg` in the working directory. You can specify a different file with `--playlist-file`.
You can provide your own Ogg file or generate it by running one of the following ffmpeg commands:

**Fake two-track Ogg with metadata (artist/title per stream)**

```sh
ffmpeg \
  -f lavfi -t 8 -i "sine=frequency=330" \
  -f lavfi -t 8 -i "sine=frequency=660" \
  -map 0:a -map 1:a \
  -c:a libopus -page_duration 20000 \
  -metadata:s:a:0 artist="WebRTC-rs Artist" -metadata:s:a:0 title="Fake Intro" \
  -metadata:s:a:1 artist="Open-Source Friend" -metadata:s:a:1 title="Fake Outro" \
  playlist.ogg
```

**Single-track fallback with tags**

```sh
ffmpeg -f lavfi -t 10 -i "sine=frequency=480" \
  -c:a libopus -page_duration 20000 \
  -metadata artist="Solo Bot" -metadata title="One Track Demo" \
  playlist.ogg
```

## Run it

1. Generate a test playlist (see above), or use your own multi-track Ogg file.

2. Run the example from the examples directory:
   ```sh
   cd rtc/examples
   cargo run --example play-from-disk-playlist-control
   # or with custom address and playlist file
   cargo run --example play-from-disk-playlist-control -- --addr localhost:8080 --playlist-file my_music.ogg
   ```

3. Open the hosted UI in your browser and press **Start Session**:
   ```
   http://localhost:8080
   ```

   Signaling is WHEP-style: the browser POSTs plain SDP to `/whep` and the server responds with the answer SDP. Use the
   buttons or type `next` / `prev` / a track number to switch tracks. Playlist metadata and now-playing updates arrive
   over the DataChannel; Opus audio flows on the media track.

## Command-line options

```
-a, --addr <ADDR>                Server address [default: 127.0.0.1:8080]
-d, --debug                      Enable debug logging
-l, --log-level <LOG_LEVEL>      Log level [default: INFO]
-o, --output-log-file <FILE>     Output log to file
-p, --playlist-file <FILE>       Playlist OGG file [default: playlist.ogg]
```
