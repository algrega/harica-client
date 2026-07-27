## Summary / Sintesi

<!-- What problem does this pull request solve, and how? / Quale problema risolve questa pull request e come? -->

## Related issue / Issue collegata

<!-- Use "Closes #123" when applicable. / Usa "Closes #123" quando applicabile. -->

## Change type / Tipo di modifica

- [ ] Bug fix / Correzione bug
- [ ] Improvement or feature / Miglioramento o funzionalità
- [ ] Documentation / Documentazione
- [ ] Tests or maintenance / Test o manutenzione
- [ ] Compatibility-breaking change / Modifica incompatibile

## Verification / Verifica

<!-- List the commands and results. / Elenca comandi e risultati. -->

```text
python -W error::ResourceWarning -m unittest discover -s tests -v
ruff check .
python -m pip wheel . --no-deps --wheel-dir dist
```

## Compatibility and documentation / Compatibilità e documentazione

<!-- Describe effects on the CLI, Python API, supported Python versions, output formats, and documentation. / Descrivi gli effetti su CLI, API Python, versioni Python, formati di output e documentazione. -->

## Security and privacy / Sicurezza e privacy

<!-- Describe any change to credentials, network behavior, certificates, cache, or exports. Never include real secrets or personal/operational data. / Descrivi modifiche a credenziali, rete, certificati, cache o esportazioni. Non includere segreti reali o dati personali/operativi. -->

## Checklist

- [ ] I followed `CONTRIBUTING.md` and the Code of Conduct. / Ho seguito `CONTRIBUTING.md` e il Codice di condotta.
- [ ] I added or updated tests when behavior changed. / Ho aggiunto o aggiornato i test se il comportamento è cambiato.
- [ ] I ran the relevant checks above. / Ho eseguito i controlli pertinenti indicati sopra.
- [ ] I updated both README variants when needed. / Ho aggiornato entrambi i README quando necessario.
- [ ] I removed API keys, certificates, private hostnames, email addresses, cache files, exports, and unsanitized logs. / Ho rimosso API key, certificati, hostname privati, indirizzi email, cache, esportazioni e log non ripuliti.
- [ ] I documented any compatibility-breaking change. / Ho documentato ogni modifica incompatibile.
