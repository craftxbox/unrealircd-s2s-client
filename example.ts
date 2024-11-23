import { ServerToServerClient, User, generateUID } from "unreal-s2s-client";

let sid = "999";

let client = new ServerToServerClient({
    port: 6900,
    host: "tor1.ca.crxb.cc",
    hostname: "test.dev.crxb.cc",
    authMethod: "spkifp",
    sid: sid,
    keyPath: "./key.pem",
    certPath: "./cert.pem",
    tlsOptions: { rejectUnauthorized: false },
});

client.onRaw = (raw) => {
    console.log(raw);
};

let AuthServUID = generateUID(sid);
let AuthServ: User = {
    nickname: "AuthServ",
    hopcount: 0,
    username: "AuthServ",
    timestamp: Math.floor(Date.now() / 1000),
    hostname: "127.0.0.1",
    uid: AuthServUID,
    usermodes: "qrtwzBSZ",
    servicestamp: "*",
    virtualhost: "test.dev.crxb.cc",
    cloakedhost: "test.dev.crxb.cc",
    ip: btoa("\x7F\x00\x00\x01"),
    gecos: "AuthServ",
    memberships: { "#services": { uid: AuthServUID, prefix: "*" } },
};

client.onSync = () => {
    client.registerUser(AuthServ);
    client.sendMessage(AuthServ.uid, "#services", "Hello, World!");
};

let approvedFingerprints: string[] = [];

client.onMessage = (from, to, message) => {
    let source = client.users[from] || client.users[client.usersByNick[from]];
    if (!source) {
        source = client.serverToUser(client.servers[from]);
    }
    if (to === "#services") {
        if (message.startsWith("approve")) {
            let [_, nickname] = message.split(" ");
            let userUid = client.usersByNick[nickname];
            let user = userUid ? client.users[userUid] : null;
            if (!user && userUid.length > 40) {
                approvedFingerprints.push(userUid);
                client.sendMessage(AuthServ.uid, source.uid, `Fingerprint ${userUid} approved.`);
                return;
            } else if (!user) {
                client.sendMessage(AuthServ.uid, source.uid, `User ${nickname} not found or invalid CertFP.`);
                return;
            }

            if (!user.moddata?.certfp) {
                client.sendMessage(AuthServ.uid, source.uid, `User ${nickname} does not have a certificate fingerprint.`);
                return;
            }
            approvedFingerprints.push(user.moddata.certfp);

            client.sendMessage(AuthServ.uid, "#services", `User ${nickname} approved.`);
            client.sendMessage(AuthServ.uid, user.uid, `You have been approved by ${source.nickname}.`);
        }
    }
    if (to === AuthServ.uid || to === AuthServ.nickname) {
        if (message.startsWith("certfp")) {
            let certfp = source.moddata?.certfp;
            if (!certfp) {
                client.sendMessage(AuthServ.uid, source.uid, "You do not have a certificate fingerprint.");
                return;
            }
            client.sendMessage(AuthServ.uid, source.uid, `Your certificate fingerprint is: ${certfp}`);
        }

        if (message.startsWith("register")) {
            let certfp = source.moddata?.certfp;
            if (!certfp) {
                client.sendMessage(AuthServ.uid, source.uid, "You do not have a certificate fingerprint.");
                return;
            }
            client.sendMessage(AuthServ.uid, "#services", `${source.nickname} Requests approval for fingerprint ${certfp}`);
            client.sendMessage(AuthServ.uid, source.uid, "Your request has been sent.");
        }

        if (message.startsWith("identify")) {
            let certfp = source.moddata?.certfp;
            if (!certfp) {
                client.sendMessage(AuthServ.uid, source.uid, "You do not have a certificate fingerprint.");
                return;
            }
            if (approvedFingerprints.includes(certfp)) {
                client.write(`SVSMODE ${source.uid} +r`);
                client.sendMessage(AuthServ.uid, "#services", `${source.nickname} has successfully authenticated.`);
                client.sendMessage(AuthServ.uid, source.uid, "You are now identified.");
            } else {
                client.sendMessage(AuthServ.uid, source.uid, "You are not approved.");
            }
        }

        console.log(`<${source.nickname}> ${message}`);
    }
};

client.connect();
