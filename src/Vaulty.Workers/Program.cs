using Microsoft.Extensions.Hosting;
using Vaulty.Workers;

// Worker host for backup, restore, verification and garbage-collection workflows. Runs under systemd (Type=notify).
var host = WorkerHost.Build(args);
await host.RunAsync();
