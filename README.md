# unreal-s2s-client

This is a simple library for interfacing with UnrealIRCD via the S2S interface.  
You can use this to make custom bridges, or custom services packages for your network, as opposed to using Atheme or Anope.

## Usage

Install the package via npm:

```bash
npm install unreal-s2s-client
```

Then, you can import it in your code like so:

```typescript
import { ServerToServerClient, User, generateUID } from "unreal-s2s-client";
```

## Example

See [example.ts](example.ts) for a full example.
