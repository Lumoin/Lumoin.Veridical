// Environment-neutral runner: no DOM access, so the same bundle runs under Node. The arguments
// after the script name are forwarded to the C# Main as Microsoft.Testing.Platform arguments, and
// Main's return value becomes the process exit code. The exit code is assigned rather than
// calling process.exit so that redirected output drains before the process ends.
//
// One argument is consumed here instead of forwarded: --trx-out <path>. When it is present the
// run writes a TRX report inside the runtime's in-memory file system, and after the run the
// report is read through the runtime's file-system API and written to <path> on the host disk.
import { dotnet } from './_framework/dotnet.js'
import { mkdirSync, writeFileSync } from 'node:fs'
import { dirname } from 'node:path'

const trxOutOption = '--trx-out';
const virtualResultsDirectory = '/trx';
const virtualTrxName = 'wasm-tests.trx';

const forwarded = [];
let trxOut = null;
const received = process.argv.slice(2);
for (let index = 0; index < received.length; index++) {
    if (received[index] === trxOutOption && index + 1 < received.length) {
        trxOut = received[++index];
    } else {
        forwarded.push(received[index]);
    }
}

if (trxOut !== null) {
    forwarded.push('--report-trx', '--report-trx-filename', virtualTrxName, '--results-directory', virtualResultsDirectory);
}

const runtime = await dotnet.withApplicationArguments(...forwarded).create();
let exitCode = await runtime.runMain();

if (trxOut !== null) {
    try {
        const report = runtime.Module.FS.readFile(`${virtualResultsDirectory}/${virtualTrxName}`);
        mkdirSync(dirname(trxOut), { recursive: true });
        writeFileSync(trxOut, report);
    } catch (error) {
        console.error(`The TRX report could not be copied to ${trxOut}: ${error}`);
        if (exitCode === 0) {
            exitCode = 1;
        }
    }
}

process.exitCode = exitCode;
