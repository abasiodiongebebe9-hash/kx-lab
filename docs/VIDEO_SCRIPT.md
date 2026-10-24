# Demonstration video script (maximum 10 minutes)

Record your screen with your voice (OBS Studio, Zoom or the built-in recorder). Aim for about 8 to 9 minutes.

| Time | What to show | What to say |
|------|--------------|-------------|
| 0:00 | Title slide or the report title page | Your name, matric number, project title, supervisor |
| 0:30 | Terminal: `git clone`, `pip install -r requirements.txt` | The project is on GitHub; how it is installed |
| 1:15 | Terminal: `python app.py`, open the browser | The application runs locally (mention the hosted link if you have one) |
| 1:45 | Register an account, log in | The first account is the administrator; passwords are stored as scrypt hashes |
| 2:30 | Simulation page: ECDH-X25519, no MITM, press Start | Walk through the timeline; the keys match; Bob decrypts the message |
| 3:30 | Switch on MITM, DH-2048, Start | Mallory replaces both public values; the keys differ; Mallory reads the message |
| 4:45 | Switch on "Require signatures", Start again | The signature check fails and the exchange stops: attack detected |
| 5:30 | RSA-2048 with MITM, no signatures | The keys match but Mallory holds a copy; matching keys do not prove safety |
| 6:15 | Dashboard: run the benchmark (20 to 50 runs) | Explain the table and the three charts: time and bytes per protocol |
| 7:15 | Terminal: `python -m unittest discover -s tests -v` | 30 tests pass: unit, integration, security |
| 8:00 | Open `backend/schema.sql` | The five tables and how they relate |
| 8:30 | Summarise the results | Which protocol is fastest and smallest, why authentication matters |
| 9:30 | End | Thank the supervisor; repeat the GitHub link |
