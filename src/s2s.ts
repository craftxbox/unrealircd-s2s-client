import tls from "tls";
import fs from "fs";

const ModeToPrefix: { [modeFlag: string]: string } = {
    v: "+",
    h: "%",
    o: "@",
    a: "~",
    q: "*",
};

type S2SClientOptions = {
    host: string;
    port: number;
    sid: string;
    hostname: string;
    authMethod: "pass" | "spkifp";
    protocolExtensions?: string[];
    serverDescription?: string;
    password?: string;
    keyPath?: string;
    certPath?: string;
    tlsOptions?: tls.ConnectionOptions;
};

export type User = {
    nickname: string;
    hopcount: number;
    timestamp: number;
    username: string;
    hostname: string;
    uid: string;
    servicestamp: string;
    usermodes: string;
    virtualhost: string;
    cloakedhost: string;
    ip: string;
    gecos: string;
    local?: boolean;
    away?: boolean;
    moddata?: { [key: string]: string };
    memberships: { [channel: string]: Member };
};

export type Server = {
    source: string;
    servername: string;
    hopcount: number;
    sid: string;
    info: string;
    moddata?: { [key: string]: string };
};

export type Member = {
    uid: string;
    prefix: string;
};

export type Channel = {
    name: string;
    timestamp: number;
    modes: string;
    users: { [member: string]: Member };
    bans: string[];
    excepts: string[];
    inviteExcepts: string[];
};

export type Topic = {
    source: string;
    channel: string;
    timestamp: number;
    topic: string;
};

export class ServerToServerClient {
    private _options: S2SClientOptions;
    private _tlsOptions: tls.ConnectionOptions;
    private _linkinfo: { [key: string]: string | boolean } = {};
    private _buffer = "";
    private _writebuffer: string[] = [];
    private _socket: tls.TLSSocket;
    private _blockEOS: boolean;

    /**
     * The users on the network, indexed by UID
     */
    users: { [uid: string]: User } = {};
    /** Like this.users but by Nickname instead of UID*/
    usersByNick: { [nickname: string]: User } = {};
    /** Servers on the network */
    servers: { [sid: string]: Server } = {};
    /** Channels on the network */
    channels: { [channel: string]: Channel } = {};
    /** If this client is destroyed */
    destroyed = false;

    /**
     * Event fired when the client is first registered with the network
     * @returns true if the client should not automatically send end of sync. You MUST call endOfSync() manually.
     */
    onRegistered: () => boolean | void = () => {};
    /**
     * Event fired when the client is fully synced with the network
     */
    onSync: () => void = () => {};
    /**
     * Event fired when a server is fully synced with the network
     */
    onServerSynced: (source: string) => void = () => {};
    /**
     * Event fired for every packet, containing the raw line from the server
     * @param raw The raw line from the server
     */
    onRaw: (raw: string) => void = () => {};
    /**
     * Event fired when the server sends a PING packet
     * @param source The source of the PING packet
     */
    onPing: (source: string) => void = () => {};
    /**
     * Event fired when the server sends UID to register a user.
     * @param source The source of the UID packet
     * @param user The user object.
     */
    onUID: (source: string, user: User) => void = () => {};
    /**
     * Event fired when the server sends SID to register a server.
     * @param server The server object.
     */
    onSID: (server: Server) => void = () => {};
    /**
     * Event fired when a user changes their nickname
     * @param source The source of the NICK packet
     * @param nickname The new nickname
     * @param timestamp The timestamp of the nickname change
     */
    onNick: (source: string, nickname: string, timestamp: number) => void = () => {};
    /**
     * Event fired when a user quits the network
     * @param source The source of the QUIT packet
     * @param quitMessage The quit message
     */
    onQuit: (source: string, quitMessage: string) => void = () => {};
    /**
     * Event fired when a user is killed from the network
     * @param source The source of the KILL packet
     * @param target The target of the KILL packet
     * @param killMessage The kill message
     */
    onKill: (source: string, target: string, killMessage: string) => void = () => {};
    /**
     * Event fired when a user's module data is modified
     * @param source The source of the MD packet
     * @param type The type of the MD packet
     * @param target The target of the MD packet
     * @param key The key being modified
     * @param value The value being set
     */
    onModData: (source: string, type: string, target: string, key: string, value: string) => void = () => {};
    /**
     * Event fired when a user joins a channel/server joins a user to a channel
     * @param source The source of the SJOIN packet
     * @param channel The channel the user joined
     */
    onSJoin: (source: string, channel: Channel) => void = () => {};
    /**
     * Event fired when a user changes the topic of a channel
     * @param topic The topic object
     */
    onTopic: (topic: Topic) => void = () => {};
    /**
     * Event fired when a user has their host changed.
     * @param source The source of the CHGHOST packet
     * @param virtualhost The new virtual host
     * @param target The target of the CHGHOST packet, undefined if self
     */
    onChgHost: (source: string, virtualhost: string, target?: string) => void = () => {};
    /**
     * Event fired when a user has their ident changed.
     * @param source The source of the CHGIDENT packet
     * @param ident The new ident
     * @param target The target of the CHGIDENT packet, undefined if self
     */
    onChgIdent: (source: string, ident: string, target?: string) => void = () => {};
    /**
     * Event fired when a user has their name changed.
     * @param source The source of the CHGNAME packet
     * @param name The new name
     * @param target The target of the CHGNAME packet, undefined if self
     */
    onChgName: (source: string, name: string, target?: string) => void = () => {};
    /**
     * Event fired when a user parts a channel
     * @param source The source of the PART packet
     * @param channel The channel the user parted
     * @param reason The reason the user parted
     */
    onPart: (source: string, channel: string, reason: string) => void = () => {};
    /**
     * Event fired when a user is kicked from a channel
     * @param source The source of the KICK packet
     * @param channel The channel the user was kicked from
     * @param target The target of the KICK packet
     * @param reason The reason the user was kicked
     */
    onKick: (source: string, channel: string, target: string, reason: string) => void = () => {};
    /**
     * Event fired when a channel mode is changed
     * @param source The source of the MODE packet
     * @param target The target of the MODE packet
     * @param modes The modes being set
     * @param args The arguments for the modes
     */
    onMode: (source: string, target: string, modes: string, args: string[]) => void = () => {};
    /**
     * Event fired when a user mode is changed
     * @param source The source of the UMODE2 packet
     * @param modes The modes being set
     */
    onUMode: (source: string, modes: string) => void = () => {};
    /**
     * Event fired when a user sends a message to a target
     * @param source The source of the PRIVMSG packet
     * @param target The target of the PRIVMSG packet
     * @param message The message being sent
     */
    onMessage: (source: string, target: string, message: string) => void = () => {};
    /**
     * Event fired when a user sends a notice to a target
     * @param source The source of the NOTICE packet
     * @param target The target of the NOTICE packet
     * @param message The message being sent
     */
    onNotice: (source: string, target: string, message: string) => void = () => {};
    /**
     * Event fired when any sourced command is received.
     * Use this for any command not already implemented.
     * @param source The source of the command
     * @param command The command received
     * @param args The arguments for the command
     */
    onCommand: (source: string, command: string, args: string[]) => void = () => {};
    /**
     * Event fired when a user requests the version of the server
     * @param source The source of the VERSION packet
     * @param args The arguments for the VERSION packet
     */
    onVersion: (source: string, args: string[]) => void = (source) => {
        this.sendNumeric(source, 351, `Unreal S2S Client - https://github.com/craftxbox/unrealircd-s2s-client`);
    };
    /**
     * Event fired when the client is disconnected from the server
     * @param err The error that caused the disconnect, if any.
     */
    onDisconnected: (err?: Error) => void = () => {};

    constructor(options: S2SClientOptions) {
        this._options = options;
        this._tlsOptions = options.tlsOptions || {};
    }

    connect(): void {
        if (this.destroyed) throw new Error("Client is destroyed");

        if (this._options.authMethod === "spkifp") {
            if (!this._options.keyPath || !this._options.certPath) {
                throw new Error("Key and Cert path required for spkifp authMethod");
            }
            this._tlsOptions.key = fs.readFileSync(this._options.keyPath);
            this._tlsOptions.cert = fs.readFileSync(this._options.certPath);
        }

        this._socket = tls.connect(this._options.port, this._options.host, this._tlsOptions, () => {
            if (this._options.authMethod === "pass") {
                this.writeRaw(`PASS :${this._options.password}`);
            } else if (this._options.authMethod === "spkifp") {
                this.writeRaw(`PASS :*`);
            }

            let protostring = (this._options.protocolExtensions || []).join(" ");

            this.writeRaw(`PROTOCTL NOQUIT NICKv2 SJOIN SJ3 NICKIP TKLEXT2 NEXTBANS ${protostring}`);
            let unix_time = Math.floor(Date.now() / 1000);
            this.writeRaw(`PROTOCTL TS=${unix_time}`);
            this.writeRaw(`PROTOCTL EAUTH=${this._options.hostname} SID=${this._options.sid}`);
            this.writeRaw(
                `SERVER ${this._options.hostname} 1 : ${this._options.serverDescription || "craftxbox/unrealircd-s2s-client@gh"}`
            );

            this._socket.on("data", (data) => this._dataHandler(data));
            this._socket.on("end", () => {
                this.onDisconnected();
            });
            this._socket.on("error", (err) => {
                this.onDisconnected(err);
            });

            this._startWriter();
        });
    }

    _dataHandler(data: string): void {
        if (this.destroyed) return;
        this._buffer += data.toString();
        let lines = this._buffer.split("\r\n");
        if (lines.length > 1) {
            if (lines[lines.length - 1] === "") {
                this._buffer = "";
            } else {
                this._buffer = lines.pop() || "";
            }

            for (let i = 0; i < lines.length; i++) {
                this._lineHandler(lines[i]);
            }
        }
    }

    _lineHandler(line: string): void {
        if (this.destroyed) return;
        this.onRaw(line);

        let parts = line.split(" ");

        let consumed: [string?] = [];
        let partsConsumed = 0;

        function consumePart(): string {
            let part = parts[partsConsumed];
            consumed.push(part);
            partsConsumed++;
            return part;
        }

        function reconstruct(): string {
            return consumed.join(" ");
        }

        if (parts[0] === "PING") {
            this._writebuffer.unshift(`PONG ${parts[1]}`);
            this.onPing(parts[1]);
        }

        if (parts[0] === "PROTOCTL") {
            for (let i = 1; i < parts.length; i++) {
                let [key, value] = parts[i].split("=");
                this._linkinfo[key] = value || true;
            }
        }

        if (parts[0] === "TOPIC") {
            let topic = {
                source: parts[2],
                channel: parts[1],
                timestamp: parseInt(parts[3]),
                topic: line.split(parts[3] + " :")[1],
            };

            this.onTopic(topic);
        }

        if (parts[0] === "NETINFO") {
            consumePart();
            let maxusers = consumePart();
            let timestamp = consumePart();
            let version = consumePart();
            let cloakhash = consumePart();
            [consumePart(), consumePart(), consumePart()]; // Skip the rest of the line
            let networkname = line.slice(reconstruct().length + 2);
            this._linkinfo["MAXUSERS"] = maxusers;
            this._linkinfo["TIMESTAMP"] = timestamp;
            this._linkinfo["VERSION"] = version;
            this._linkinfo["CLOAKHASH"] = cloakhash;
            this._linkinfo["NETWORKNAME"] = networkname;
            if (!this._blockEOS) {
                this.endOfSync();
            }
            this.onSync();
        }

        if (parts[0] === "SERVER") {
            this._blockEOS = this.onRegistered() == true;
        }

        if (parts[0].startsWith(":")) {
            let source = consumePart().slice(1);
            let command = consumePart();

            if (command === "EOS") {
                this.onServerSynced(source);
            }

            if (command === "UID") {
                let user: User = {
                    nickname: consumePart(),
                    hopcount: parseInt(consumePart()),
                    timestamp: parseInt(consumePart()),
                    username: consumePart(),
                    hostname: consumePart(),
                    uid: consumePart(),
                    servicestamp: consumePart(),
                    usermodes: consumePart(),
                    virtualhost: consumePart(),
                    cloakedhost: consumePart(),
                    ip: consumePart(),
                    gecos: line.slice(reconstruct().length + 2),
                    memberships: {},
                };
                this.users[user.uid] = user;
                this.usersByNick[user.nickname] = user;
                this.onUID(source, user);
            }

            if (command === "SID") {
                let server = {
                    source: source,
                    servername: consumePart(),
                    hopcount: parseInt(consumePart()),
                    sid: consumePart(),
                    info: line.slice(reconstruct().length + 2),
                };
                this.servers[server.sid] = server;
                this.onSID(server);
            }

            if (command === "NICK") {
                delete this.usersByNick[this.users[source].nickname];
                this.users[source].nickname = parts[2];
                this.usersByNick[parts[2]] = this.users[source];
                this.onNick(source, parts[2], parseInt(parts[3]));
            }

            if (command === "QUIT") {
                delete this.usersByNick[this.users[source].nickname];
                delete this.users[source];
                let quitMessage = line.slice(reconstruct().length + 2);
                this.onQuit(source, quitMessage);
            }

            if (command === "KILL") {
                let killMessage = line.slice(reconstruct().length + 2);
                this.onKill(source, parts[2], killMessage);
            }

            if (command === "MD") {
                if (this.users[parts[3]]) {
                    let moddata = this.users[parts[3]].moddata || {};
                    if (parts[5] == undefined) {
                        delete moddata[parts[4]];
                    } else {
                        moddata[parts[4]] = parts[5].slice(1);
                        this.users[parts[3]].moddata = moddata;
                    }
                } else if (this.servers[parts[3]]) {
                    let moddata = this.servers[parts[3]].moddata || {};
                    if (parts[5] == undefined) {
                        delete moddata[parts[4]];
                    } else {
                        moddata[parts[4]] = parts[5].slice(1);
                        this.servers[parts[3]].moddata = moddata;
                    }
                }
                this.onModData(source, parts[2], parts[3], parts[4], parts[5]);
            }

            if (command === "SETHOST") {
                this.users[source].virtualhost = parts[2];
                this.onChgHost(source, parts[2]);
            }

            if (command === "SETIDENT") {
                this.users[source].username = parts[2];
                this.onChgIdent(source, parts[2]);
            }

            if (command === "SETNAME") {
                this.users[source].gecos = line.split(parts[2] + " :")[1];
                this.onChgName(source, line.split(parts[2] + " :")[1]);
            }

            if (command === "CHGHOST") {
                this.users[parts[2]].virtualhost = parts[3];
                this.onChgHost(source, parts[3], parts[2]);
            }

            if (command === "CHGIDENT") {
                this.users[parts[2]].username = parts[3];
                this.onChgIdent(source, parts[3], parts[2]);
            }

            if (command === "CHGNAME") {
                this.users[parts[2]].gecos = line.split(parts[3] + " :")[1];
                this.onChgName(source, line.split(parts[3] + " :")[1], parts[2]);
            }

            if (command === "SJOIN") {
                let timestamp = parseInt(consumePart());
                let name = consumePart();
                let modes = parts[partsConsumed].startsWith("+") ? consumePart() : "";

                let channel: Channel = this.channels[name] || {
                    timestamp: timestamp,
                    name: name,
                    modes: modes,
                    users: {},
                    bans: [],
                    excepts: [],
                    inviteExcepts: [],
                };

                let unsafe = false;

                if (this.channels[name]) {
                    let incumbent = this.channels[name];
                    if (timestamp == incumbent.timestamp) {
                        let newModes: { [mode: string]: boolean } = {};
                        for (let mode of modes) {
                            if (mode == "+") continue;
                            newModes[mode] = true;
                        }
                        for (let mode of incumbent.modes) {
                            if (mode == "+") continue;
                            newModes[mode] = true;
                        }
                        channel.modes = Object.keys(newModes).join("");
                    } else if (timestamp < incumbent.timestamp) {
                        channel.modes = modes;
                    } else {
                        unsafe = true;
                    }
                }

                let sjoinbuffer: string[] = line
                    .split(reconstruct() + " :")[1]
                    .trim()
                    .split(" ");

                for (let i of sjoinbuffer) {
                    if (i == "") continue;
                    if (i.startsWith("&")) {
                        channel.bans.push(i.slice(1));
                        continue;
                    }
                    if (i.startsWith('"')) {
                        channel.excepts.push(i.slice(1));
                        continue;
                    }
                    if (i.startsWith("'")) {
                        channel.inviteExcepts.push(i.slice(1));
                        continue;
                    }

                    let uid = i;
                    let prefix = "";

                    let regex = /^([^\w]*)([0-9A-Z]{3,}$)/;
                    let match = i.match(regex) || [i, "", i];

                    prefix = unsafe ? "" : match[1];
                    uid = match[2];

                    let user = this.users[uid];

                    let membership = {
                        uid: user.uid,
                        prefix: prefix,
                    };

                    channel.users[user.nickname] = membership;
                    user.memberships[name] = membership;
                }

                this.channels[name] = channel;

                this.onSJoin(source, channel);
            }

            if (command === "PART") {
                let channel = consumePart();
                let user = this.users[source];
                delete user.memberships[channel];
                delete this.channels[channel].users[user.nickname];

                if (Object.keys(this.channels[channel].users).length === 0) {
                    delete this.channels[channel];
                }

                let reason = line.slice(reconstruct().length + 2);

                this.onPart(source, channel, reason);
            }

            if (command === "KICK") {
                let channel = consumePart();
                let target = consumePart();
                let user = this.users[target];
                delete user.memberships[channel];
                delete this.channels[channel].users[user.nickname];

                if (Object.keys(this.channels[channel].users).length === 0) {
                    delete this.channels[channel];
                }

                let reason = line.slice(reconstruct().length + 2);

                this.onKick(source, channel, target, reason);
            }

            if (command === "SAJOIN") {
                let target = consumePart();
                let channel = consumePart();

                let user = this.users[target];

                if (!user.local) return;

                let membership = {
                    uid: user.uid,
                    prefix: this.channels[channel] ? "" : "@",
                };

                let channelObj = this.channels[channel] || {
                    timestamp: Math.floor(Date.now() / 1000),
                    name: channel,
                    modes: "+nt",
                    users: {},
                    bans: [],
                    excepts: [],
                    inviteExcepts: [],
                };

                channelObj.users[user.nickname] = membership;
                user.memberships[channel] = membership;
                this.write(`SJOIN ${channelObj.timestamp} ${channelObj.name} ${channelObj.modes} :${membership.prefix + membership.uid}`);
                this.onSJoin(target, channelObj);
            }

            if (command === "SAPART") {
                let target = consumePart();
                let channel = consumePart();

                let user = this.users[target];
                delete user.memberships[channel];
                delete this.channels[channel].users[user.nickname];

                if (Object.keys(this.channels[channel].users).length === 0) {
                    delete this.channels[channel];
                }

                let reason = line.slice(reconstruct().length + 2);
                reason = reason ? "SAPart:" + reason : "";

                this.writeRaw(`:${target} PART ${channel} :${reason}`);
            }

            if (command === "MODE") {
                let target = consumePart();
                let modes = consumePart();
                let args = parts.slice(partsConsumed);

                let channelObj = this.channels[target];

                let incumbentModes = channelObj.modes;

                if (source.length == 3) {
                    let timestamp = args.pop();
                }

                let newModes: { [mode: string]: boolean } = {};

                for (let mode of modes) {
                    if (mode == "+") continue;
                    newModes[mode] = true;
                }

                let addModes = modes.split("-")[0].slice(1);

                for (let mode of addModes) {
                    if (mode == "+") continue;
                    if ("vhoaq".includes(mode)) {
                        let arg = args.shift();
                        if (!arg) continue;
                        let prefix = ModeToPrefix[mode];
                        channelObj.users[arg].prefix += prefix;
                    } else if ("beI".includes(mode)) {
                        let arg = args.shift();
                        if (!arg) continue;
                        switch (mode) {
                            case "b":
                                channelObj.bans.push(arg);
                                break;
                            case "e":
                                channelObj.excepts.push(arg);
                                break;
                            case "I":
                                channelObj.inviteExcepts.push(arg);
                                break;
                        }
                    } else {
                        newModes[mode] = true;
                    }
                }

                let removeModes = modes.split("-")[1] || "";

                for (let mode of removeModes) {
                    if (mode == "+") continue;
                    if ("vhoaq".includes(mode)) {
                        let arg = args.shift();
                        if (!arg) continue;
                        let prefix = ModeToPrefix[mode];
                        channelObj.users[arg].prefix = channelObj.users[arg].prefix.replace(prefix, "");
                    } else if ("beI".includes(mode)) {
                        let arg = args.shift();
                        switch (mode) {
                            case "b":
                                channelObj.bans = channelObj.bans.filter((ban) => ban !== arg);
                                break;
                            case "e":
                                channelObj.excepts = channelObj.excepts.filter((except) => except !== arg);
                                break;
                            case "I":
                                channelObj.inviteExcepts = channelObj.inviteExcepts.filter((inviteExcept) => inviteExcept !== arg);
                                break;
                        }
                    } else {
                        delete newModes[mode];
                    }
                }

                channelObj.modes = "+" + Object.keys(newModes).join("");
                this.channels[target] = channelObj;
                this.onMode(source, target, modes, parts.slice(partsConsumed));
            }

            if (command === "UMODE2") {
                let user = this.users[source] || this.usersByNick[source];
                let modes = consumePart();

                let newModes: { [mode: string]: boolean } = {};

                for (let mode of user.usermodes) {
                    if (mode == "+") continue;
                    newModes[mode] = true;
                }

                let add = true;
                for (let mode of modes) {
                    if (mode == "+") {
                        add = true;
                        continue;
                    } else if (mode == "-") {
                        add = false;
                        continue;
                    }
                    if (add) newModes[mode] = true;
                    else delete newModes[mode];
                }
                user.usermodes = "+" + Object.keys(newModes).join("");
                this.users[user.uid] = user;
                this.onUMode(source, modes);
            }

            if (command === "PRIVMSG") {
                let target = consumePart();
                let message = line.slice(reconstruct().length + 2);
                this.onMessage(source, target, message);
            }

            if (command === "NOTICE") {
                let target = consumePart();
                let message = line.slice(reconstruct().length + 2);
                this.onNotice(source, target, message);
            }

            if (command === "VERSION") {
                this.onVersion(source, parts.slice(partsConsumed));
            }

            this.onCommand(source, command, parts.slice(partsConsumed));
        }
    }

    /**
     * Write a raw line to the server
     * @param raw The raw line to write
     */
    writeRaw(raw: string): void {
        this._writebuffer.push(raw + "\r\n");
    }

    /**
     * Write a message to the server, prepending the SID
     * @param message The message to write
     */
    write(message: string): void {
        let data = `:${this._options.sid} ${message}`;
        this.writeRaw(data);
    }

    /**
     * Introduce a user to the network
     * @param user The user to introduce
     * @param noSJoin If true, do not send SJOIN packets for the user. Take care to manually send SJOIN packets for the user, or you will be desynced.
     */
    registerUser(user: User, noSJoin?: boolean): void {
        let message = ["UID"];
        message.push(user.nickname);
        message.push(user.hopcount.toString());
        message.push(user.timestamp.toString());
        message.push(user.username);
        message.push(user.hostname);
        message.push(user.uid);
        message.push(user.servicestamp);
        message.push(user.usermodes);
        message.push(user.virtualhost);
        message.push(user.cloakedhost);
        message.push(user.ip);
        message.push(":" + user.gecos);
        this.write(message.join(" "));

        this.users[user.uid] = user;
        this.usersByNick[user.nickname] = user;

        if (noSJoin) return;

        for (let name in user.memberships) {
            let membership = user.memberships[name];
            let channel = this.channels[name] || {
                timestamp: Math.floor(Date.now() / 1000),
                name: name,
                modes: "+nt",
                users: { [user.nickname]: membership },
                bans: [],
                excepts: [],
                inviteExcepts: [],
            };
            let message = ["SJOIN"];
            message.push(channel.timestamp.toString());
            message.push(channel.name);
            message.push(channel.modes);
            message.push(":" + membership.prefix + membership.uid);
            this.write(message.join(" "));
        }
    }

    /**
     * Introduce a server to the network
     * @param server The server to introduce
     */
    registerServer(server: Server): void {
        let message = ["SID"];
        message.push(server.servername);
        message.push(server.hopcount.toString());
        message.push(server.sid);
        message.push(":" + server.info);
        this.write(message.join(" "));
    }

    /**
     * Send a message to a target
     * @param source The source of the message
     * @param target The target of the message
     * @param message The message to send
     */
    sendMessage(source: string, target: string, message: string): void {
        this.writeRaw(`:${source} PRIVMSG ${target} :${message}`);
    }

    /**
     * Send a notice to a target
     * @param source The source of the notice
     * @param target The target of the notice
     * @param message The message to send
     */
    sendNotice(source: string, target: string, message: string): void {
        this.writeRaw(`:${source} NOTICE ${target} :${message}`);
    }

    /**
     * Send a numeric reply to a target
     * @param target The target of the numeric
     * @param numeric The numeric to send
     * @param message The message to send
     */
    sendNumeric(target: string, numeric: string | number, message: string): void {
        numeric = typeof numeric === "number" ? numeric.toString() : numeric;
        while (numeric.length < 3) {
            numeric = "0" + numeric;
        }
        numeric = numeric.slice(0, 3);

        this.write(`${numeric} ${target} ${message}`);
    }

    /**
     * Join users to a channel
     * @param channel The channel to join the users to
     * @param members The members to join to the channel
     */
    sjoinToChannel(channel: Channel, ...members: Member[]): void {
        if (!this.channels[channel.name]) {
            this.channels[channel.name] = channel;
        }

        let buffer = "SJOIN " + timestamp();
        buffer += " " + channel.name;
        buffer += " " + channel.modes;
        buffer += " :";

        members.forEach((member) => {
            if (!this.users[member.uid]) {
                throw new Error(`User ${member.uid} not registered`);
            }

            if (this.users[member.uid].memberships[channel.name]) {
                throw new Error(`User ${member.uid} is already in channel ${channel.name}`);
            }

            buffer += member.prefix + member.uid + " ";
            channel.users[this.users[member.uid].nickname] = member;
            this.users[member.uid].memberships[channel.name] = member;
        });

        this.write(buffer);
    }

    /**
     * Convert a Server into a User.
     * @param server The server to convert
     */
    serverToUser(server: Server): User {
        return {
            nickname: server.servername,
            hopcount: server.hopcount,
            timestamp: 0,
            username: server.servername,
            hostname: server.servername,
            uid: server.sid,
            servicestamp: "*",
            usermodes: "S",
            virtualhost: server.servername,
            cloakedhost: server.servername,
            ip: btoa("\x00\x00\x00\x00"),
            gecos: server.info,
            memberships: {},
        };
    }

    endOfSync(): void {
        this.write("EOS");
        this.writeRaw(`NETINFO 0 ${timestamp()} 6100 * 0 0 0 :${this._linkinfo["NETWORKNAME"] || ""}`);
    }

    async _startWriter(): Promise<void> {
        while (true) {
            if (this._writebuffer.length > 0) {
                let data = this._writebuffer.splice(0, 64).join("");
                if (process.env["S2S_WRITE_DEBUG"] === "true") console.log("> " + data);
                this._socket.write(data);
            }
            if (this._writebuffer.length > 0) {
                // We only want to slow down if there's more data to write. 
                await new Promise((resolve) => setTimeout(resolve, 100));
            } else {
                await new Promise((resolve) => setTimeout(resolve,1));
            }
        }
    }

    /**
     * Disconnect from the server
     * Does not send QUIT packets
     * @param reason The reason for the disconnect
     */
    disconnect(reason = "Software Requested Disconnect", graceful?: boolean): void {
        if (graceful) {
            Object.keys(this.users)
                .filter((uid) => uid.startsWith(this._options.sid))
                .forEach((uid) => {
                    this.writeRaw(`:${uid} QUIT :Server Shutting Down.`);
                });
        }
        this.writeRaw(`:${this._options.sid} SQUIT ${this._options.hostname} :${reason}`);
        this._socket.end();
        this.destroyed = true;
        this.onDisconnected();
    }
}

/**
 * Generate a UID for a user
 * @returns The generated UID, prefixed with the SID
 */
export function generateUID(sid: string): string {
    return sid + Math.random().toString(36).slice(2, 8).toUpperCase();
}

export function timestamp() {
    return Math.floor(Date.now() / 1000);
}

export default ServerToServerClient;
