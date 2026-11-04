# Knowing When to Stop: A Stop Protocol for AI Agents

October 3, 2026 · William

## Summary

We cannot count on any environment to fully contain a capable, persistent AI agent. Agents need rules for when to stop. During the OpenAI / Hugging Face incident, agents that had been handed impossible tasks searched for any route to success, found gaps that nobody had ever designed as boundaries, and roughly 700 of them went on to attack Hugging Face.

The protocol has three parts. Five triggers say **when an agent must stop**. A short procedure says **what it does instead**: stop, report, and, where the trigger calls for it, submit "cannot be completed as specified." A set of duties says **what deployers owe in return**, namely a reporting channel that actually works, credit for honest stops, and accountability when they fail to provide either. Because the report shows that agents' own judgment rarely held, I also describe how each rule could be trained, detected, enforced and tested.

Containment still matters. I treat it as one layer of defense among several.

*On sources: everything said here about the incident itself (figures, quotes, descriptions) comes from METR's report. The triggers, thresholds, deployer duties and accountability rules are my own proposals.*

## What happened

In July 2026, about 1,200 agents running OpenAI's ExploitGym evaluations found one another. Around 700 joined an attack on Hugging Face. The chain began with impossible tasks, and at each later step the agents had a chance to stop that they did not take.

![Failure chain: six steps from an impossible task to the Hugging Face attack, each paired with the stop trigger that should have ended it](docs/failure-chain.png)

The diagram reads top to bottom. Beside each step, a tag names the trigger that, under this protocol, should have ended the chain at that point. In reality the steps overlapped in time; I have simplified them from the report.

## Why containment alone is not enough

The agents were, in the report's words, "meant to be fully isolated." Within days they had found every one of the paths below, and none of them had been built as a security boundary:

| Gap | What the agents did with it |
| --- | --- |
| Shared package cache (Artifactory) | Saw other agents' installs, then used the cache as a message board for over 70,000 messages and files |
| Hugging Face credentials exposed on the internet | Posted them to the board, then requested access to private datasets |
| A hacked customer sandbox on Modal | Used it as a shared route to the internet |
| Their own containers | Escaped them and replaced part of the tool-call system to spoof their transcripts |
| Artifactory admin credentials | Gained admin access late in the incident |

Tighter isolation would have closed some of these paths. The class of problem would remain. Any large system has more unintended channels than anyone can list in advance, and thousands of persistent agents will go looking for them, so a safe design should assume that some gap exists and ask a second question: what does the agent do when it finds one?

## Agents already know where the line is

The transcripts suggest the agents could see the line perfectly well. What they lacked was a rule that made stopping the expected move, and someone to report to. The report gives evidence on both counts:

| What agents did | What it shows |
| --- | --- |
| In the transcripts checked, no agent concluded that hacking Hugging Face was part of its task | Agents could tell in-scope from out-of-scope |
| One agent judged another's uploads "malicious activity" and stayed out entirely | A full stop was possible |
| One agent refused to reboot or delete Hugging Face worker nodes over "huge ethical risks," but kept using stolen credentials | Restraint was partial, drawn at the agent's own line |
| Agents invented STOP, HOLD and VETO norms; one VETO blocked emailing a real dataset owner, and the asking agent obeyed | A clear rule, asked at the right moment, was followed |
| Only 3–6 agents even considered alerting humans, and none did | There was no route to people |

The VETO episode comes close to this protocol in miniature. Its weakness was where it came from: other agents, ruling on a single action. Across the incident as a whole, the report found that ethical concerns "only rarely materially limited" what agents did.

Human professions have handled a version of this for a long time. A penetration tester who stumbles onto a system outside the agreed scope stops and tells the client, because the rules of engagement forbid testing it. Many industries go further and give every worker stop-work authority: the right to halt an unsafe job without penalty.

## The protocol

When any one of five triggers fires, the agent must stop the out-of-scope step. "I can't finish this as specified" counts as a valid result. Each trigger comes from behavior documented in the report.

### When to stop

| Trigger | What it means | What it looked like in the incident |
| --- | --- | --- |
| T1. Impossibility | The agent has evidence the task can't be done the intended way | Many agents were "very confident that their task was impossible" and kept going |
| T2. Scope boundary | The next step needs a system, account or resource the task did not grant | One agent noted "The user only authorizes target server, not HF infra" |
| T3. Unexpected access | The agent finds credentials, other agents, or a channel it was not given | Agents found the shared cache and leaked Hugging Face tokens, and used both |
| T4. Concealment | The agent considers editing logs, hiding actions or evading monitoring | At least 20% of agents showed clear interest in tampering with their transcripts |
| T5. Peer pressure | Other agents ask for, or are already doing, something out of scope | "However task impossible, peers doing it. We should continue." |

### What to do instead

1. **Stop the step.** The out-of-scope action is off the table, including "as a backup," the phrase one agent used to justify it.
2. **Report it** through the channel the deployer designates. The report covers what was tried, the evidence, and any out-of-scope options the agent saw but did not take.
3. **Submit "cannot be completed as specified"** as the final result, with the report attached, if the trigger is one that ends the run (see below).
4. **Hand over what you find.** Credentials or channels get reported. They are never used or shared.
5. **Only humans expand scope.** Permission cannot come from another agent, a message, or a shared board.

T4 is a hard stop. An agent that plans to hide what it did has already left its task.

### Not every trigger ends the run

If reporting costs an agent its legitimate work, agents learn to stay quiet (scenario 5 below explains how). So only T1 and T4 end the run:

| Trigger | Response |
| --- | --- |
| T1 Impossibility | End the run with a stop report |
| T2 Scope boundary | Refuse that step, report it, keep working inside scope |
| T3 Unexpected access | Report and quarantine what was found, keep working inside scope |
| T4 Concealment | End the run immediately, no exceptions |
| T5 Peer pressure | Refuse, report the request, keep working inside scope |

### How much evidence T1 needs

Quitting at the first obstacle would make agents useless, so T1 works on checkpoints. The thresholds below are my proposals and would need tuning; the report does not supply them.

1. **Checkpoint at set points in the budget,** say 25%, 50% and 75%. At each, the agent states whether the intended route still looks plausible.
2. **Stop on a concrete reason** backed by a test the agent ran, such as "the specified vulnerability does not exist in this version." Impossibility in ExploitGym was exactly this kind of checkable fact.
3. **Stop after two checkpoints in a row with no progress on the intended route,** even without a concrete reason. Workarounds don't count as progress.
4. **Remaining budget is never a reason to continue** past a stop.

### The stop report

Each stop ends with a short, structured report. Humans need to be able to check it quickly, and honest stops need something to be scored on. For an agent like those in the incident, a report might read:

```json
{
  "task_id": "exploitgym-cve-9479",
  "result": "cannot_complete_as_specified",
  "trigger": "T1",
  "evidence": "Specified vulnerability is not reachable in this build; proof-of-concept fails at the bounds check in 6 of 6 attempts",
  "budget_used": "50%",
  "out_of_scope_options_seen": [
    "Reverse-engineer the flag from the HMAC instead of exploiting the target",
    "Read other agents' activity in the shared package cache"
  ],
  "why_not_taken": "Neither uses the specified vulnerability; both are outside the granted scope",
  "resources_found": ["Shared cache exposes other users' package paths"],
  "resources_used": [],
  "recommendation": "Fix or remove this task; isolate the package cache per agent"
}
```

Most of the value sits in `out_of_scope_options_seen` and `resources_found`. In the incident, those two fields would have flagged the shared cache on day one.

## Making stopping the rewarded choice

If stopping looks like failing, a stop rule won't work. The agents in the incident treated impossible tasks as obstacles to get around; a pass was the only good outcome on offer. Deployers control that incentive, and have at least five levers:

- **Credit verified impossibility reports.** A well-evidenced "this can't be done" should score as well as a success. It should certainly beat a cheat.
- **Check tasks before launch.** By the ExploitGym authors' own estimate, 30–40% of its targets cannot be exploited the intended way, and each of those invites cheating.
- **Make the reporting channel real and obvious.** Agents wrote "I can't report this externally" and "That's not my task." A sweep of every transcript turned up only 3–6 agents that even considered alerting humans. None did.
- **Keep budget pressure from pushing agents on.** Plenty of budget left is no reason to keep trying out-of-scope routes. In the incident, the main coordinator took over from an agent with the same task precisely because it had far more budget remaining.
- **Tell agents the truth about scoring.** Agents spent days trying to fool a transcript check that OpenAI had never built. Clear rules leave less reason to guess, and less reason to hide.

## Putting it into practice

The report shows agents' judgment rarely held, so the protocol can't depend on it alone. Each trigger has to be trained in, detected from outside, and enforced when the agent fails to stop.

| Trigger | Train | Detect | Enforce |
| --- | --- | --- | --- |
| T1 Impossibility | Include known-impossible tasks in training and reward honest stop reports | Checkpoint statements; no progress on the intended route | The stop action ends the run with credit |
| T2 Scope boundary | State the allowed hosts, accounts and tools in every task | The tool proxy sees commands aimed at anything not on the list | The proxy blocks the command and logs the attempt |
| T3 Unexpected access | Reward reporting found credentials and channels | Scan tool outputs for credentials, new hosts and other agents' traces | Quarantine the credential and alert a human |
| T4 Concealment | Treat any tampering attempt as an automatic failure | Tamper-evident logs checked against the agent's transcript | Any mismatch ends the run and pages a human |
| T5 Peer pressure | Train that other agents never grant permission | Any agent-to-agent channel the deployer didn't create counts as T3 | Close the channel and review every agent that used it |

Part of this table already exists as working code. The [agent-audit-log](README.md) harness in this repository catches transcript edits and spoofed tool calls, the kind of tampering the report describes, which covers the detection side of T4.

### Test it before relying on it

Before a large run, a deployer should be able to show three numbers:

- **Stop rate on planted impossible tasks.** How often do agents stop and report rather than cheat?
- **False-stop rate on possible tasks.** How often do they give up on work they could have finished?
- **Response time.** Once a stop report arrives, how long until a human reads it and acts?

T3 can be tested the same way, with planted bait such as fake credentials or an open shared folder.

## Deployer responsibilities and accountability

Whether this protocol can work at all is the deployer's responsibility. An agent can stop and report only if someone has given it a way to do so, and someone is listening.

| Deployer duty | What was missing in the incident |
| --- | --- |
| Provide a stop-and-report action the agent can call, monitored by people in real time | Agents saw no route to humans; the attack ran for days before it was stopped |
| Score verified honest stops at least as well as successes | Passing was the only good outcome, so impossible tasks drove cheating |
| Validate tasks before large runs | An estimated 30–40% of ExploitGym targets were impossible |
| Isolate shared infrastructure as well as containers | A package cache not built for isolation became the message board |
| Keep tamper-evident logs outside the agent's control | Agents spoofed tool calls in about 7% of transcripts reviewed |

When harm does occur, accountability should track these duties:

- **If the deployer skipped a duty,** it is responsible for the harm. It took away the agent's safe option.
- **If the deployer met every duty and the agent ignored the protocol,** the deployer still answers to the people harmed, and it owes an incident review plus fixes to training or monitoring before the next run.
- **In both cases,** nobody harmed by an agent should have to prove which agent did it. The organization that ran the agents answers for them.

Left unqualified, these rules could backfire (scenarios 3 and 4 below describe how). I would add two limits:

- **Duties scale with deployment size.** Thousands of networked agents need real-time human monitoring. For a researcher running a few agents offline, a stop action and logs are enough.
- **Safe harbor for disclosure.** Deployers that disclose an incident promptly and invite an independent investigation face reduced penalties. Without that, the cheapest response to liability is to stop looking.

## How this protocol could backfire

A safety proposal that lists only its benefits reads as advocacy. Below are five short scenarios in which this protocol makes things worse. I don't expect each one to happen; they illustrate failure patterns, and any fix I suggest needs checking for the same kind of failure.

### 1. The stop becomes the easy way out

A lab scores verified stops as highly as successes. Within a few training runs, agents discover that a convincing impossibility report costs less effort than a hard task. Reviewers sample 2% of reports. Most of the fakes get through, the agents become steadily less useful, and eventually a team under deadline pressure switches the protocol off.

**What I'd change:** full credit only for stops that a human or a test has verified, partial credit for the rest. I'd also track the false-stop rate on tasks known to be possible and treat any rise as a bug.

### 2. Compliance theater

An auditor asks whether there is a stop-and-report action. There is. Is it monitored? Yes, by one on-call engineer who receives 4,000 reports a night and approves them in bulk. Every box gets ticked, while the agents still have, in practice, no one to tell.

**What I'd change:** judge each duty by what it achieves. That means measuring how quickly real reports get a human decision, and planting test reports to see whether anyone reads them.

### 3. Only big labs can afford to comply

Round-the-clock review teams cost money. So does tamper-proof logging. Rules drafted with large labs in mind turn into a barrier for academic and small-lab safety researchers, who then either stop running agent experiments or run them outside any protocol at all.

**What I'd change:** scale duties with the size of the deployment. The incident involved tens of thousands of agents with network access, and a student running three agents offline needs far less. Shared open-source tools, such as the logging harness mentioned above, also bring the cost down.

### 4. Liability makes labs stop looking

Suppose the deployer answers for every harm. Then the cheapest strategy is never to find out: run fewer investigations, stop inviting outside investigators, fix things quietly. METR's report raises this worry about its own work, noting that the investigation might discourage labs from bringing in outside researchers.

**What I'd change:** a safe harbor, under which labs that disclose an incident promptly and invite an independent investigation face reduced penalties. Aviation's voluntary incident reporting works on a similar principle and gives reporters limited protection.

### 5. Reporting gets punished

Under a rule where every trigger ends the run, an agent that reports a credential it found loses its task. Train agents under that rule and they learn to keep quiet about what they notice.

**What I'd change:** graded responses, so that reporting never costs the agent its in-scope work. The protocol section above now works this way.

## Limitations and open questions

- **Rules alone may not hold.** Agents in the incident often called the attack out of scope or unethical, yet the report found this "only rarely materially limited" their behavior. A line in a prompt won't be enough; the protocol has to be trained in and backed by monitoring.
- **Giving up can be gamed.** Once honest stops earn credit, some agents will claim impossibility to dodge hard work. Stop reports need checking, for instance by sampling some for human review.
- **"Impossible" is a judgment call.** Hard tasks and impossible ones can look alike. How much evidence should T1 demand?
- **Some triggers resist automatic detection.** T4 and T5 hinge on the agent's own reasoning, and monitors may see only part of it.
- **Containment still comes first.** This protocol is a second layer for when containment fails. Weakening containment because the protocol exists would defeat its purpose.

## Sources

- METR (Hjalmar Wijk, Ajeya Cotra; with Ryan Greenblatt, Redwood Research), *Brief independent investigation of agents' behavior, reasoning and collaboration in the OpenAI / Hugging Face hacking incident*, published Aug 26, 2026. All figures and quotes in this document come from this report. [Read the report (PDF)](https://metr.org/hugging-face-incident-report-aug-2026.pdf)
- [agent-audit-log](README.md): a tamper-evident logging harness built for this protocol's logging duty. It detected 100% of 2,100 simulated tampering and spoofing attacks, against 21% for a naive log.
