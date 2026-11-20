(
var sceneRoot = thisProcess.nowExecutingPath.dirname;
var visuals;

if(OSCVisuals.sceneReplayVersion != 1) {
    Error("VisualsQuark scene replay API 1 is required").throw
};

visuals = OSCVisuals("127.0.0.1", 33333);
visuals.replay({ |scene|
    scene.send('/layers/reset', 0, "stack");
}, sceneRoot: sceneRoot, width: 800, height: 600,
   rendererRoot: sceneRoot, finalGate: -1, replyTimeout: 15.0,
   onComplete: { |status, frame, detail|
       "scene replay: % frame=% detail=%".format(status, frame, detail).postln;
   });

~exportedScene = visuals;
)
