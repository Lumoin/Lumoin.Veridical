// Environment-neutral runner: no DOM access, so the same bundle runs under Node. The arguments
// after the script name are forwarded to the C# Main as Microsoft.Testing.Platform arguments, and
// Main's return value becomes the process exit code. The exit code is assigned rather than
// calling process.exit so that redirected output drains before the process ends.
//
// One argument is consumed here instead of forwarded: --trx-out <path>. When it is present the
// run writes a TRX report inside the runtime's in-memory file system, and after the run the
// report is read through the runtime's file-system API and written to <path> on the host disk.
//
// A second argument is consumed too: --diag-out <directory>. When it is present the run enables
// the Microsoft Testing Platform diagnostic log at Trace verbosity and the runtime's own
// diagnostic tracing, and every write the run makes under the runtime's diagnostic directory is
// also appended to a file of the same name in <directory> on the host as it happens. A run that
// stalls inside WebAssembly code never returns control to this script, so a copy made after the
// run would never happen; mirroring each write is what makes the log readable after a stalled run
// is stopped. The runtime's file-system layer has no host-directory mount linked in, so the
// mirroring wraps its write function.
import { dotnet } from './_framework/dotnet.js'
import { appendFileSync, mkdirSync, writeFileSync } from 'node:fs'
import { basename, dirname, join } from 'node:path'

const trxOutOption = '--trx-out';
const virtualResultsDirectory = '/trx';
const virtualTrxName = 'wasm-tests.trx';
const diagOutOption = '--diag-out';
const virtualDiagDirectory = '/diag';

const forwarded = [];
let trxOut = null;
let diagOut = null;
const received = process.argv.slice(2);
for (let index = 0; index < received.length; index++) {
    if (received[index] === trxOutOption && index + 1 < received.length) {
        trxOut = received[++index];
    } else if (received[index] === diagOutOption && index + 1 < received.length) {
        diagOut = received[++index];
    } else {
        forwarded.push(received[index]);
    }
}

if (trxOut !== null) {
    forwarded.push('--report-trx', '--report-trx-filename', virtualTrxName, '--results-directory', virtualResultsDirectory);
}

if (diagOut !== null) {
    forwarded.push('--diagnostic', '--diagnostic-verbosity', 'Trace', '--diagnostic-output-directory', virtualDiagDirectory);
}

// The runtime's environment is separate from Node's, so the variable that varies the seeds of the
// agreement sweeps is copied across when it is set.
const seedVariable = 'VERIDICAL_TEST_SEED';
let builder = dotnet.withApplicationArguments(...forwarded);
if (process.env[seedVariable] !== undefined) {
    builder = builder.withEnvironmentVariable(seedVariable, process.env[seedVariable]);
}

if (diagOut !== null) {
    builder = builder.withDiagnosticTracing(true);
}

const runtime = await builder.create();
if (diagOut !== null) {
    mkdirSync(diagOut, { recursive: true });
    const fileSystem = runtime.Module.FS;
    fileSystem.mkdir(virtualDiagDirectory);
    const originalWrite = fileSystem.write;
    fileSystem.write = function (stream, buffer, offset, length, ...rest) {
        const written = originalWrite.call(this, stream, buffer, offset, length, ...rest);
        if (typeof stream.path === 'string' && stream.path.startsWith(`${virtualDiagDirectory}/`)) {
            appendFileSync(join(diagOut, basename(stream.path)), buffer.subarray(offset, offset + written));
        }

        return written;
    };
}

let exitCode = await runtime.runMain(runtime.getConfig().mainAssemblyName, forwarded);

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
