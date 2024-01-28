OSCVisuals {
    classvar <tab, <nl;

	var <net;

	*initClass {
		tab = [$\\, $\\, $t].as(String);
		nl = [$\\, $\\, $n].as(String);
	}

	*new { arg hostname, port;
		var inst = super.newCopyArgs(NetAddr(hostname, port));
		inst.send('/layers/reset', 9);
		^inst;
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