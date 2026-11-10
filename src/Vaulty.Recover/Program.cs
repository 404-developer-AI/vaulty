using Vaulty.Recover;

// vaulty-recover: rebuilds a tenant from object storage alone, without the database. See RecoverCommand for the options.
return await RecoverCommand.RunAsync(args, Console.Out, Console.Error, Environment.GetEnvironmentVariable).ConfigureAwait(false);
