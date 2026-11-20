// Private implementation for OSCVisuals:replay. These classes are not public API.
OSCVisualsReplayRecorder : OSCVisuals {
	var commands, alive;

	*fromNet { |net, commandList|
		^super.newCopyArgs(net).initReplayRecorder(commandList)
	}

	initReplayRecorder { |commandList|
		commands = commandList;
		alive = true;
		^this
	}

	expire {
		alive = false;
	}

	checkAlive {
		if(alive.not) { Error("replay recorder has expired").throw };
	}

	send { |address ...args|
		this.checkAlive;
		commands.add(OSCVisualsReplay.normalizeCommand(address, args));
	}

	sendRaw { |address ...args|
		var copiedAddress;
		this.checkAlive;
		if(args.any { |value| value.class === Array }) {
			Error("raw replay commands do not support Array arguments").throw
		};
		copiedAddress = address.asString.copy;
		commands.add([copiedAddress] ++ args.collect { |value| if(value.isString) { value.copy } { value } });
	}

	replay { |body, sceneRoot, width, height, rendererRoot, finalGate = -1, replyTimeout = 15.0, onComplete|
		Error("nested replay on a replay recorder is not allowed").throw
	}
}

OSCVisualsReplay {
	classvar allowedAddresses, vectorAddresses;

	*initClass {
		allowedAddresses = ["/layers/reset", "/input", "/input/set", "/var", "/shader", "/shader/var", "/tex",
			"/shader/texture", "/tex/var", "/tex/size", "/tex/speed", "/tex/set", "/shader/texture/size",
			"/shader/texture/speed", "/shader/texture/set", "/layer/pos", "/layer/rot", "/layer/scale",
			"/layer/pivot", "/layer/size", "/layer/tint", "/layer/alpha", "/layer/bri", "/layer/speed",
			"/layer/visible", "/layer/align", "/layer/blend"];
		vectorAddresses = ["/layer/pos", "/layer/rot", "/layer/scale", "/layer/pivot", "/layer/size", "/layer/tint"];
	}

	*fail { |text|
		Error("scene preflight: " ++ text).throw
	}

	*utf8Bytes { |value|
		var total = 0;
		value.do { |char| var code = char.asUnicode;
			total = total + if(code <= 127, 1, { if(code <= 2047, 2, { if(code <= 65535, 3, 4) }) });
		};
		^total
	}

	*strictString { |value, allowEmpty = true|
		^value.isString and: { allowEmpty or: { value.size > 0 } } and: {
			value.every { |char| char.asUnicode != 0 }
		} and: { this.utf8Bytes(value) <= 2048 }
	}

	*strictInt { |value|
		^value.isInteger and: { value >= -2147483648 and: { value <= 2147483647 } }
	}

	*strictFloat { |value|
		^value.isFloat and: { value.isNaN.not and: { value.abs <= 1000000 } }
	}

	*validateSettings { |sceneRoot, rendererRoot, width, height, finalGate, replyTimeout, onComplete|
		if(this.strictString(sceneRoot, false).not or: {
			rendererRoot.notNil and: { this.strictString(rendererRoot, false).not }
		}) { this.fail("invalid scene root settings") };
		if(this.strictInt(width).not or: { width < 64 or: { width > 2048 } } or: {
			this.strictInt(height).not or: { height < 64 or: { height > 2048 } }
		}) { this.fail("invalid renderer dimensions") };
		if(this.strictInt(finalGate).not or: { [-1, 0, 1].includes(finalGate).not }) {
			this.fail("invalid final onset gate")
		};
		if(this.strictFloat(replyTimeout).not or: { replyTimeout <= 0 or: { replyTimeout > 60 } }) {
			this.fail("invalid reply timeout")
		};
		if(onComplete.notNil and: { onComplete.isKindOf(Function).not }) {
			this.fail("onComplete must be a Function or nil")
		};
	}

	*normalizeCommand { |addressValue, sourceArgs|
		var address = addressValue.asString.copy;
		var args = sourceArgs.collect { |value|
			if(value.class === Array) {
				value.collect { |component| if(component.isString) { component.copy } { component } }
			} {
				if(value.isString) { value.copy } { value }
			}
		};
		if(this.strictString(address, false).not or: { allowedAddresses.includesEqual(address).not }) {
			this.fail("unsupported setup address: " ++ address)
		};
		if(vectorAddresses.includesEqual(address) and: { args.size == 2 and: { args[1].class === Array } }) {
			args = [args[0]] ++ args[1]
		};
		if(["/shader/var", "/tex/var"].includesEqual(address) and: { args.size == 3 and: { args[2].class === Array } }) {
			args = [args[0], args[1]] ++ args[2]
		};
		if(args.any { |value| value.class === Array }) { this.fail("Array is only supported at a known vector position") };
		args.do { |value| if(value.isString.not and: { value.isInteger.not and: { value.isFloat.not } }) {
			this.fail("unsupported command value: " ++ value)
		} };
		^[address] ++ args
	}

	*perform { |target, commands, sceneRoot, rendererRoot, width, height, finalGate, replyTimeout, onComplete|
		var replyPort = NetAddr.langPort;
		var token, randomFile, randomBytes = Int8Array.newClear(16), bytesRead;
		var responder, completed = false, messages, bundleBytes, finish;
		var layerCount = -1, inputs = Set.new, shaders = Set.new, defaults = Set.new, samplers = Set.new;
		var isNumber = { |value| value.isFloat or: { value.isString and: { value.size > 0 } } };
		var asciiAlpha = { |char| var code = char.asUnicode;
			(code >= 65 and: { code <= 90 }) or: { code >= 97 and: { code <= 122 } }
		};
		var strictIdentifier = { |value| this.strictString(value, false) and: { this.utf8Bytes(value) <= 64 } and: {
			asciiAlpha.(value[0]) or: { value[0] == $_ }
		} and: { value.every { |char| asciiAlpha.(char) or: { char.isDecDigit or: { char == $_ } } } } };
		var strictReserved = ["camPos", "camLook", "camOrbit"].asSet;
		var strictInputs = Set.new, strictShared = Set.new, strictAssigned = Set.new, strictWillAssign = Set.new;
		var strictShaders = Set.new, strictDefaults = Set.new, strictSamplers = Set.new, strictAssets = Dictionary.new;
		var strictBindings, strictPhase = 0, strictComponents = 0, strictFragmentBytes = 0, strictImageBytes = 0;
		var strictExpr, strictNumber, strictAsset;
		var feedbackLayer, feedbackSettings = Dictionary.new, feedbackSize = false, feedbackSpeed = false, feedbackControls = Set.new;
		var feedbackReserved = ["size", "speed", "color", "tint", "timePct", "time", "resolution", "srctex", "randomSeed", "random", "mouse", "frame", "modelViewProjectionMatrix", "modelViewMatrix", "projectionMatrix", "textureMatrix", "globalColor", "usingTexture", "usingColors"].asSet;

		if(replyPort.isInteger.not or: { replyPort < 1024 or: { replyPort > 65535 } }) { this.fail("reply port outside 1024..65535") };
		if(commands.size < 1 or: { commands.size > 2048 }) { this.fail("command count outside 1..2048") };
		strictAsset = { |name, kind| var parts, path, size, known;
			if(this.strictString(name, false).not or: { name.beginsWith("assets/").not or: { name.includes($\\) } }) { this.fail("unsafe asset path") };
			parts = name.split($/);
			if(parts.size < 2 or: { parts.any { |part| part.size == 0 or: { part == "." or: { part == ".." } } } }) { this.fail("unsafe asset components") };
			if(([\fragment, \feedback_fragment].includes(kind) and: { name.endsWith(".frag").not }) or: { kind == \image and: { name.endsWith(".png").not } }) { this.fail("asset suffix does not match command") };
			known = strictAssets.at(name);
			if(known.notNil and: { known != kind }) { this.fail("asset used with conflicting kinds") };
			if(known.isNil) {
				path = sceneRoot +/+ name;
				if(File.type(path) != \regular) { this.fail("asset is missing or not a regular file: " ++ name) };
				size = File.fileSize(path);
				if(size.isInteger.not or: { size < 0 }) { this.fail("cannot size asset: " ++ name) };
				if([\fragment, \feedback_fragment].includes(kind)) {
					if(size > 131072) { this.fail("fragment asset exceeds 131072 bytes") };
					strictFragmentBytes = strictFragmentBytes + size
				} { strictImageBytes = strictImageBytes + size };
				strictAssets.put(name, kind);
				if(strictAssets.size > 64 or: { strictFragmentBytes > 1048576 or: { strictImageBytes > 4194304 } }) { this.fail("aggregate asset bound exceeded") };
			};
		};
		strictExpr = { |expression| var matches;
			if(this.strictString(expression, false).not) { this.fail("invalid expression string") };
			matches = expression.findRegexp("[A-Za-z_][A-Za-z0-9_]*");
			matches.do { |pair| var index = pair[0], name = pair[1], suffix = expression.copyToEnd(index + name.size), next;
				next = suffix.detect { |char| char.isSpace.not };
				if((next != $() and: { ["left", "right", "top", "bottom", "center", "pi", "e", "i", "total"].includesEqual(name).not }) {
					if(strictReserved.includesEqual(name)) { this.fail("expression references reserved camera variable") };
					if(strictShared.includesEqual(name)) {
						if(strictWillAssign.includesEqual(name) and: { strictAssigned.includesEqual(name).not }) { this.fail("shared expression dependency used before assignment") };
					} {
						if(["t", "f"].includesEqual(name).not and: { name.beginsWith("in_").not or: { strictInputs.includesEqual(name.copyToEnd(3)).not } }) { this.fail("unresolved expression reference: " ++ name) };
					};
				};
			};
		};
		strictNumber = { |value| if(this.strictFloat(value)) { strictComponents = strictComponents + 1 } {
			if(value.isString) { strictComponents = strictComponents + 1; strictExpr.(value) } { this.fail("invalid numeric/expression component") }
		} };
		commands.do { |cmd| if(cmd.isArray and: { cmd.size == 3 and: { cmd[0] == "/var" and: { cmd[1].isString and: { cmd[2].isString } } } }) {
			strictWillAssign.add(cmd[1])
		} };
		commands.do { |cmd, i| var address, args, layer, tail, key, kinds, binding;
			if(cmd.isArray.not or: { cmd.size < 1 or: { this.strictString(cmd[0], false).not } }) { this.fail("invalid command array at index " ++ i) };
			address = cmd[0]; args = cmd.drop(1);
			if(allowedAddresses.includesEqual(address).not) { this.fail("unsupported setup address: " ++ address) };
			args.do { |value|
				if(value.isString and: { this.strictString(value).not }) { this.fail("invalid command string at index " ++ i) };
				if(value.isFloat and: { this.strictFloat(value).not }) { this.fail("nonfinite or out-of-range float at index " ++ i) };
				if(value.isInteger and: { this.strictInt(value).not }) { this.fail("out-of-range integer at index " ++ i) };
			};
			if(address == "/layers/reset") {
				if(i != 0 or: { args.size != 2 or: { this.strictInt(args[0]).not or: { args[0] < 0 or: { args[0] > 32 } } } or: { ["stack", "grid", "col", "row"].includesEqual(args[1]).not } }) { this.fail("invalid /layers/reset") };
				layerCount = args[0]; strictBindings = Array.fill(layerCount, { Set.new });
			} {
				if(layerCount < 0) { this.fail("/layers/reset must be first") };
				if(address == "/input") {
					if(strictPhase != 0 or: { args.size != 4 }) { this.fail("input ordering/arity is invalid") };
					key = args[0].asString;
					if((args[0].isString and: { strictIdentifier.(args[0]) and: { strictReserved.includesEqual(args[0]).not } }).not and: { this.strictInt(args[0]).not or: { args[0] < 0 } }) { this.fail("invalid input identifier") };
					if(strictInputs.includesEqual(key)) { this.fail("duplicate input") };
					strictInputs.add(key); if(strictInputs.size > 16) { this.fail("too many inputs") };
				};
				if(address == "/input/set" and: { strictPhase != 0 }) { this.fail("input setting follows shared/dependent command") };
				if(address == "/var") {
					if(args.size != 2 or: { strictIdentifier.(args[0]).not or: { strictReserved.includesEqual(args[0]) } }) { this.fail("invalid shared variable") };
					if(args[1].isFloat) {
						if(strictPhase > 1 or: { strictShared.includesEqual(args[0]) }) { this.fail("shared bootstrap ordering is invalid") };
						strictPhase = 1; strictShared.add(args[0]); if(strictShared.size > 64) { this.fail("too many shared variables") }; strictComponents = strictComponents + 1;
					} {
						if(args[1].isString.not or: { strictPhase > 2 or: { strictShared.includesEqual(args[0]).not or: { strictAssigned.includesEqual(args[0]) } } }) { this.fail("shared assignment ordering/type is invalid") };
						strictPhase = 2; strictNumber.(args[1]); strictAssigned.add(args[0]);
					};
				};
				if(["/input", "/input/set", "/var"].includesEqual(address).not) {
					strictPhase = 3;
					if(args.size < 1 or: { this.strictInt(args[0]).not or: { args[0] < 0 or: { args[0] >= layerCount } } }) { this.fail("invalid layer index") };
					layer = args[0]; tail = args.drop(1); binding = nil;
					if(address == "/shader") { if(tail.size != 1 or: { strictShaders.includesEqual(layer) }) { this.fail("invalid or duplicate shader source") }; strictAsset.(tail[0], \fragment); strictShaders.add(layer) };
					if(address == "/tex") {
						if(tail.size != 1 or: { strictDefaults.includesEqual(layer) or: { tail[0].isString.not } }) { this.fail("invalid or duplicate default source") };
						if(tail[0].beginsWith("shader_pp:")) {
							if(feedbackLayer.notNil) { this.fail("only one feedback source is supported") };
							strictAsset.(tail[0].copyToEnd(10), \feedback_fragment); feedbackLayer = layer;
						} { strictAsset.(tail[0], \image) }; strictDefaults.add(layer)
					};
					if(address == "/tex/var") {
						if(layer != feedbackLayer or: { tail.size < 2 or: { tail.size > 5 } } or: { strictIdentifier.(tail[0]).not or: { feedbackReserved.includesEqual(tail[0]) or: { tail[0].beginsWith("gl_") } } }) { this.fail("invalid feedback control") };
						if(tail.drop(1).every { |value| this.strictFloat(value) }.not) { this.fail("feedback controls require constant float components") };
						if(feedbackControls.includesEqual(tail[0])) { this.fail("duplicate feedback control") };
						feedbackControls.add(tail[0]); if(feedbackControls.size > 64) { this.fail("too many feedback controls") };
						strictComponents = strictComponents + tail.size - 1; binding = "feedback:" ++ tail[0];
					};
					if(address.beginsWith("/tex/") and: { layer == feedbackLayer }) {
						if(address == "/tex/size") {
							if(feedbackSize or: { tail.size != 2 } or: { tail.every { |value| this.strictFloat(value) and: { value == value.floor } }.not } or: { tail[0] < 1 or: { tail[0] > 800 or: { tail[1] < 1 or: { tail[1] > 600 } } } }) { this.fail("invalid feedback dimensions") }; feedbackSize = true;
						};
						if(address == "/tex/speed") { if(tail.size != 1 or: { this.strictFloat(tail[0]).not or: { tail[0] != 1.0 or: { feedbackSpeed } } }) { this.fail("feedback speed must be constant 1") }; feedbackSpeed = true };
						if(address == "/tex/set") {
							if(tail.size != 2 or: { tail[0].isString.not or: { this.strictInt(tail[1]).not } }) { this.fail("invalid feedback setting") };
							if(feedbackSettings.includesKey(tail[0])) { this.fail("duplicate feedback setting") };
							if((Dictionary["internalformat" -> [32856], "textureTarget" -> [3553], "blendMode" -> [0], "aspectRatio" -> [1], "static" -> [0, 1], "noClear" -> [0], "filter" -> [9729], "minFilter" -> [9729], "magFilter" -> [9729]]).at(tail[0]).isNil) { this.fail("unsupported feedback setting") };
							if((Dictionary["internalformat" -> [32856], "textureTarget" -> [3553], "blendMode" -> [0], "aspectRatio" -> [1], "static" -> [0, 1], "noClear" -> [0], "filter" -> [9729], "minFilter" -> [9729], "magFilter" -> [9729]]).at(tail[0]).includes(tail[1]).not) { this.fail("invalid feedback storage value") };
							feedbackSettings.put(tail[0], tail[1]);
						};
					};
					if(address == "/shader/var") {
						if(tail.size < 2 or: { tail.size > 5 or: { strictIdentifier.(tail[0]).not or: { strictReserved.includesEqual(tail[0]) } } }) { this.fail("invalid shader uniform") };
						kinds = Set.new;
						tail.drop(1).do { |value| if(value.isString) { strictNumber.(value) } {
							if(value.isFloat) { kinds.add(\float) } { if(value.isInteger) { kinds.add(\int) } { this.fail("invalid uniform component") } };
							strictComponents = strictComponents + 1
						} };
						if(kinds.size > 1) { this.fail("uniform numeric components mix integer and float") }; binding = "uniform:" ++ tail[0];
					};
					if(address == "/shader/texture") { if(tail.size != 2 or: { strictIdentifier.(tail[0]).not or: { strictReserved.includesEqual(tail[0]) } }) { this.fail("invalid sampler binding") }; key = layer.asString ++ ":" ++ tail[0]; if(strictSamplers.includesEqual(key)) { this.fail("duplicate sampler binding") }; strictAsset.(tail[1], \image); strictSamplers.add(key); binding = "sampler:" ++ tail[0] };
					if(address.endsWith("/speed") or: { ["/layer/alpha", "/layer/bri"].includesEqual(address) }) { strictNumber.(tail.last) };
					if(vectorAddresses.includesEqual(address)) { tail.do(strictNumber) };
					if(address == "/layer/visible") { if(tail.size == 1 and: { tail[0].isString }) { strictNumber.(tail[0]) } { strictComponents = strictComponents + 1 } };
					if(address == "/layer/size") { if(tail[0].isFloat and: { tail[0] <= 0 or: { tail[0] > 2048 } }) { this.fail("invalid layer width") }; if(tail[1].isFloat and: { tail[1] <= 0 or: { tail[1] > 2048 } }) { this.fail("invalid layer height") }; if(tail[2].isFloat and: { tail[2] != 0 }) { this.fail("layer size z must be zero") } };
					if(address.endsWith("/size") and: { address != "/layer/size" }) { tail.keep(-2).do { |value| if(this.strictFloat(value).not or: { value <= 0 or: { value > 2048 } }) { this.fail("invalid texture dimensions") }; strictComponents = strictComponents + 1 } };
					if(address.beginsWith("/layer/")) { binding = address };
					if(address.beginsWith("/tex/")) { binding = address ++ if(address == "/tex/set", ":" ++ tail[0], "") };
					if(address.beginsWith("/shader/texture/")) { if(strictIdentifier.(tail[0]).not or: { strictReserved.includesEqual(tail[0]) }) { this.fail("invalid sampler control identifier") }; binding = address ++ ":" ++ tail[0] ++ if(address.endsWith("/set"), ":" ++ tail[1], "") };
					if(binding.notNil) { strictBindings[layer].add(binding); if(strictBindings[layer].size > 128) { this.fail("holder exceeds 128 distinct bindings") } };
				};
			};
			if(strictComponents > 1024) { this.fail("recipe exceeds 1024 scalar components") };
		};

		if(feedbackLayer.notNil) {
			if(feedbackSettings.includesKey("filter") and: { feedbackSettings.includesKey("minFilter") or: { feedbackSettings.includesKey("magFilter") } }) { this.fail("feedback filter settings overlap") };
			if(feedbackSize.not or: { feedbackSpeed.not } or: { (feedbackSettings.at("filter") == 9729 or: { feedbackSettings.at("minFilter") == 9729 and: { feedbackSettings.at("magFilter") == 9729 } }).not } or: { ["internalformat", "textureTarget", "blendMode", "aspectRatio", "static"].every { |key| feedbackSettings.includesKey(key) }.not }) { this.fail("incomplete feedback setup") };
		};

		// Preserve the original independent structural pass as a second fail-closed check.
		layerCount = -1; inputs = Set.new; shaders = Set.new; defaults = Set.new; samplers = Set.new;
		commands.do { |cmd, i|
			var address = cmd[0], args = cmd.drop(1), ok = false, layer, tail, key;
			if((address == "/layers/reset") and: { i == 0 } and: { args.size == 2 } and: { args[0].isInteger } and: { args[0] >= 0 and: { args[0] <= 32 } } and: { args[1].isString } and: { ["stack", "grid", "col", "row"].includesEqual(args[1]) }) { layerCount = args[0]; ok = true } {
				if(layerCount >= 0) {
					if(address == "/input") { ok = (args.size == 4) and: { args[0].isString or: { args[0].isInteger and: { args[0] >= 0 } } } and: { args[1].isString } and: { args[2].isInteger and: { args[2] >= 0 and: { args[2] <= 32 } } } and: { args[3].isInteger and: { args[3] >= 64 and: { args[3] <= 8192 } } } and: { (args[2] == 0) or: { args[1].size > 0 } }; if(ok) { inputs.add(args[0].asString) } };
					if(address == "/input/set") { ok = (args.size == 3) and: { inputs.includesEqual(args[0].asString) } and: { ["maxAmp", "maxLoud"].includesEqual(args[1]) } and: { args[2].isFloat } and: { (args[1] != "maxAmp") or: { args[2] > 0 } } };
					if(address == "/var") { ok = (args.size == 2) and: { args[0].isString } and: { isNumber.(args[1]) } };
					if((address.beginsWith("/layer/") or: { address.beginsWith("/shader") or: { address.beginsWith("/tex") } }) and: { args.size > 0 and: { args[0].isInteger and: { args[0] >= 0 and: { args[0] < layerCount } } } }) {
						layer = args[0]; tail = args.drop(1);
						if(address == "/shader") { ok = (tail.size == 1) and: { tail[0].isString }; if(ok) { shaders.add(layer) } };
						if(address == "/tex") { ok = (tail.size == 1) and: { tail[0].isString }; if(ok) { defaults.add(layer) } };
						if(address == "/shader/var") { ok = shaders.includes(layer) and: { tail.size >= 2 and: { tail.size <= 5 } } and: { tail[0].isString } and: { tail.drop(1).every { |value| value.isString or: { value.isFloat or: { value.isInteger } } } } };
						if(address == "/shader/texture") { ok = shaders.includes(layer) and: { tail.size == 2 } and: { tail[0].isString and: { tail[1].isString } }; if(ok) { key = layer.asString ++ ":" ++ tail[0]; ok = samplers.includes(key).not; samplers.add(key) } };
						if(address == "/tex/var") { ok = (layer == feedbackLayer) };
						if(["/tex/size", "/tex/speed", "/tex/set"].includesEqual(address)) { ok = defaults.includes(layer) };
						if(address.beginsWith("/shader/texture/")) { key = layer.asString ++ ":" ++ tail[0]; ok = (tail.size > 0) and: { tail[0].isString } and: { samplers.includesEqual(key) }; tail = tail.drop(1) };
						if(ok and: { address.endsWith("/size") }) { ok = (tail.size == 2) and: { tail.every { |value| value.isFloat and: { value > 0 and: { value <= 2048 } } } } };
						if(ok and: { address.endsWith("/speed") }) { ok = (tail.size == 1) and: { isNumber.(tail[0]) } };
						if(ok and: { address.endsWith("/set") } and: { (address != "/tex/set") or: { layer != feedbackLayer } }) { ok = (tail.size == 2) and: { tail[0].isString } and: { tail[1].isInteger } and: { ((["aspectRatio", "static"].includesEqual(tail[0])) and: { [0, 1].includes(tail[1]) }) or: { (tail[0] == "blendMode") and: { tail[1] >= 0 and: { tail[1] <= 5 } } } } };
						if(["/layer/pos", "/layer/rot", "/layer/scale", "/layer/pivot", "/layer/size"].includesEqual(address)) { ok = (tail.size == 3) and: { tail.every(isNumber) } };
						if(address == "/layer/tint") { ok = (tail.size == 4) and: { tail.every(isNumber) } };
						if(["/layer/alpha", "/layer/bri", "/layer/speed"].includesEqual(address)) { ok = (tail.size == 1) and: { isNumber.(tail[0]) } };
						if(address == "/layer/visible") { ok = (tail.size == 1) and: { tail[0].isString or: { tail[0].isInteger and: { [0, 1].includes(tail[0]) } } } };
						if(address == "/layer/align") { ok = (tail.size == 2) and: { [0,1,2,4].includes(tail[0]) } and: { [0,16,32,64].includes(tail[1]) } };
						if(address == "/layer/blend") { ok = (tail.size == 1) and: { tail[0].isInteger and: { tail[0] >= 0 and: { tail[0] <= 5 } } } };
					};
				};
			};
			if(ok.not) { Error("invalid scene command at index " ++ i ++ ": " ++ cmd).throw };
		};

		randomFile = File("/dev/urandom", "rb");
		if(randomFile.isOpen.not) { this.fail("cannot open OS randomness source") };
		protect { bytesRead = randomFile.read(randomBytes) } { randomFile.close };
		if(bytesRead !== randomBytes or: { bytesRead.size != 16 }) { this.fail("cannot read 128 bits from OS randomness source") };
		token = randomBytes.collect { |byte| byte.bitAnd(255).asHexString(2) }.join;
		messages = [["/scene/reset", token, replyPort, width, height]] ++ commands.collect { |cmd, i|
			var args = cmd.copy, address = args.removeAt(0);
			if(address == "/shader" or: { address == "/tex" }) {
				args[1] = if(address == "/tex" and: { args[1].beginsWith("shader_pp:") }) {
					"shader_pp:" ++ (rendererRoot +/+ args[1].copyToEnd(10))
				} { rendererRoot +/+ args[1] };
			};
			if(address == "/shader/texture") { args[2] = rendererRoot +/+ args[2] };
			["/scene/command", token, i + 1, address] ++ args
		} ++ [["/scene/replay/end", token, replyPort, commands.size, finalGate]];
		bundleBytes = 16 + messages.sum { |message| 4 + message.asRawOSC.size };
		if(bundleBytes > 61440) { Error("scene bundle exceeds 61440 bytes").throw };

		finish = { |status, frame, detail|
			if(completed.not) {
				completed = true;
				if(responder.notNil) { responder.free; responder = nil };
				("VOSC_SCENE_RESULT " ++ status.asString ++ " frame=" ++ frame ++ " detail=" ++ detail).postln;
				if(onComplete.notNil) {
					try { onComplete.value(status, frame, detail) } { |error|
						("OSCVisuals replay completion callback failed: " ++ error).warn
					};
				};
			};
		};
		responder = OSCFunc({ |msg, time, addr, port|
			// VOSC sends replies from a fresh UDP socket, so its source port is ephemeral.
			if((port == replyPort) and: { addr.ip == target.ip } and: { msg.size == 5 } and: {
				(msg[1].class == Symbol) and: { msg[1].asString == token }
			} and: { (msg[2].class == Symbol) and: { ["applied", "failed"].includesEqual(msg[2].asString) } } and: {
				msg[3].isInteger and: { msg[3] >= -1 and: { msg[3] <= 2147483647 } }
			} and: { (msg[2].asString != "applied") or: { msg[3] >= 0 } } and: {
				msg[4].class == Symbol and: { this.utf8Bytes(msg[4].asString) <= 512 }
			}) { finish.(msg[2].asString.asSymbol, msg[3], msg[4].asString) };
		}, '/scene/replay/result', nil);
		SystemClock.sched(replyTimeout, { if(completed.not) { finish.(\unknown, -1, "timeout") }; nil });
		try {
			target.sendBundle(nil, *messages);
			"VOSC_SCENE_RESULT sent".postln;
		} { |error|
			finish.(\unknown, -1, "transport error");
			error.throw;
		};
	}
}
