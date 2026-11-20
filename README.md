# Visuals Quark

SuperCollider client classes for [VOSC](https://github.com/kasparsj/vosc).

## Scene replay API

This checkout adds the unpublished scene replay API version `1`. VOSC scene exports
use it to validate a complete editable scene and send that scene as one bounded,
immediate OSC bundle:

```supercollider
var visuals = OSCVisuals("127.0.0.1", 33333);

if(OSCVisuals.sceneReplayVersion != 1) {
    Error("VisualsQuark scene replay API 1 is required").throw
};

visuals.replay({ |scene|
    scene.send('/layers/reset', 1, "stack");
    scene.send('/shader', 0, "assets/example.frag");
    scene.send('/layer/pos', 0, [0.0, 0.0, 0.0]);
}, sceneRoot: thisProcess.nowExecutingPath.dirname,
   width: 800, height: 600,
   rendererRoot: thisProcess.nowExecutingPath.dirname,
   finalGate: -1, replyTimeout: 15.0,
   onComplete: { |status, frame, detail|
       [status, frame, detail].postln;
   });
```

`rendererRoot` may be `nil`, in which case it defaults to `sceneRoot`.
`onComplete` is optional and is called at most once with `\applied`, `\failed`,
or `\unknown`, after reply observation has been cleaned up. A timeout is
`\unknown`; replay is not retried automatically.

The object passed to the body is a short-lived `OSCVisuals` recorder. Its
`send` and `sendRaw` calls are captured for validation and become invalid as
soon as the body returns. Use the original `visuals` object for ordinary live
messages before or after replay.

The replay implementation preserves `send`, `sendRaw`, `prStringify`, `net`, and
the default constructor's no-reset behavior. It does not install or update the
Quark automatically and does not change the renderer protocol.

## Constructor reset

`OSCVisuals(host, port, reset: true)` retains the expanded reset sequence from
the locally installed Quark: `/cam/reset`, `/layers/reset`,
`/layers/layout "stack"`, `/shading ""`, then `/shading/passes` with no arguments.
This resets the camera and layers, restores stack layout, disables deferred
shading and clears shading passes. Upstream previously sent only `/layers/reset`.
VOSC still queues the shading commands until its onset gate allows them through;
the constructor does not provide an atomic or immediately completed scene reset.
The default `reset: false` and scene replay's constructor use send no reset packets.

## Local use and upgrades

These replay changes are currently local and unpublished. Select this checkout
explicitly in the SuperCollider class-library configuration used to execute a
VOSC export. Do not copy it over an installed Quark automatically. When a future
published VisualsQuark release advertises `OSCVisuals.sceneReplayVersion == 1`,
upgrade through your normal manual Quarks workflow and remove the local class
path after verifying the same API.

## Isolated tests

With the stock SuperCollider application installed:

```sh
python3 tests/run_tests.py
```

The test launcher compiles stock classes plus this checkout in an owned process,
suppresses user startup files, uses private non-default UDP ports, and records
receipts in a fresh temporary directory reported at the end of the run. Pass a
new, non-existing destination with `--output PATH` when a stable receipt path is
needed; the launcher refuses to replace an existing path. It does not install
classes, boot an audio server, or touch a running language.
