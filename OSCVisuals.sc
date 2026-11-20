OSCVisuals {
    classvar <tab, <nl;

	var <net, replaying = false;

	*initClass {
		tab = [$\\, $\\, $t].as(String);
		nl = [$\\, $\\, $n].as(String);
	}

	*new { arg hostname, port, reset=false;
		var inst = super.newCopyArgs(NetAddr(hostname, port));
		if (reset, {
			// todo: should be able to select what to reset
			inst.send('/cam/reset');
			inst.send('/layers/reset');
			inst.send('/layers/layout', "stack");
			inst.send('/shading', "");
			inst.send('/shading/passes');
		});
		^inst;
	}

	*sceneFeedbackReplayVersion {
		^1
	}

	*sceneReplayVersion {
		^1
	}

	send { |...args|
		(1..args.size).do { |i|
			if (args[i].isString.not and: {args[i].isKindOf(SequenceableCollection) or: {args[i].isKindOf(Dictionary)}}, {
				args[i] = this.prStringify(args[i]);
			});
		};
		net.sendMsg(*args);
	}

	sendRaw { |...args|
		net.sendMsg(*args);
	}

	replay { |body, sceneRoot, width, height, rendererRoot, finalGate = -1, replyTimeout = 15.0, onComplete|
		var commands = List.new;
		var recorder;

		if(replaying) { Error("nested replay on the same OSCVisuals instance is not allowed").throw };
		if(body.isKindOf(Function).not) { Error("replay requires a Function body").throw };
		OSCVisualsReplay.validateSettings(sceneRoot, rendererRoot, width, height, finalGate, replyTimeout, onComplete);

		replaying = true;
		recorder = OSCVisualsReplayRecorder.fromNet(net, commands);
		protect {
			body.value(recorder);
			recorder.expire;
			OSCVisualsReplay.perform(
				net, commands.asArray, sceneRoot, rendererRoot ? sceneRoot,
				width, height, finalGate, replyTimeout, onComplete
			);
		} {
			recorder.expire;
			replaying = false;
		};
	}

	prStringify { |obj|
		var out;

		if(obj.isString, {
			^obj.asCompileString.reject(_.isControl).replace("\n", nl).replace("\t", tab);
		});
		if(obj.class === Symbol, {
			^this.prStringify(obj.asString)
		});

		if(obj.isKindOf(Dictionary), {
			out = List.new;
			obj.keysValuesDo({ arg key, value;
				out.add( key.asString.asCompileString ++ ":" + this.prStringify(value) );
			});
			^("{" ++ (out.join(", ")) ++ "}");
		});

		if(obj.isNil, {
			^"null"
		});
		if(obj === true, {
			^"true"
		});
		if(obj === false, {
			^"false"
		});
		if(obj.isNumber, {
			if(obj.isNaN, {
				^"null"
			});
			if(obj === inf, {
				^"null"
			});
			if(obj === (-inf), {
				^"null"
			});
			^obj.asString
		});
		if(obj.isKindOf(SequenceableCollection), {
			^"[" ++ obj.collect({ arg sub;
				this.prStringify(sub)
			}).join(", ")
			++ "]";
		});

		// obj.asDictionary -> key value all of its members

		// datetime
		// "2010-04-20T20:08:21.634121"
		// http://en.wikipedia.org/wiki/ISO_8601

		("No JSON conversion for object" + obj).warn;
		^this.prStringify(obj.asCompileString)
	}
}
