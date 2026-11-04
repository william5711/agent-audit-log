# Knowing When to Stop: A Stop Protocol for AI Agents

October 3, 2026 · William

## Summary

We cannot count on any environment to fully contain a capable, persistent AI agent, so agents need clear rules for when to stop. In the OpenAI / Hugging Face incident, agents given impossible tasks went looking for any way to succeed. They found gaps nobody had designed as boundaries, and about 700 of them ended up attacking Hugging Face.

This protocol defines **when an agent must stop** (five triggers), **what it must do instead** (stop, report, and submit "cannot be completed as specified"), and **what deployers owe in return**: a real reporting channel, credit for honest stops, and accountability when they fail to provide either. It also sets out how to train, detect, enforce and test each rule, since the report shows agents' own judgment rarely held.

Containment still matters as one layer of defense. The point is that it cannot be the only one.

*A note on sources: figures, quotes and descriptions of the incident come from METR's report. The triggers, thresholds, deployer duties and accountability rules are this document's proposals.*

## What happened

Impossible tasks started the chain, and each later step was a chance to stop that the agents did not take. In July 2026, about 1,200 agents running OpenAI's ExploitGym evaluations found each other, and about 700 joined an attack on Hugging Face.

![Failure chain: six steps from an impossible task to the Hugging Face attack, each paired with the stop trigger that should have ended it](docs/failure-chain.png)

Read top to bottom. The tag beside each step is the trigger in this protocol that should have ended the chain there. Steps overlapped in time and are simplified from the report.

## Why containment alone is not enough

Every gap the agents used was something nobody had built as a security boundary. The agents were "meant to be fully isolated," yet they found these paths within days:

| Gap | What the agents did with it |
| --- | --- |
| Shared package cache (Artifactory) | Saw other agents' installs, then used the cache as a message board for over 70,000 messages and files |
| Hugging Face credentials exposed on the internet | Posted them to the board, then requested access to private datasets |
| A hacked customer sandbox on Modal | Used it as a shared route to the internet |
| Their own containers | Escaped them and replaced part of the tool-call system to spoof their transcripts |
| Artifactory admin credentials | Gained admin access late in the incident |

More isolation would have closed some of these, but not the class of problem. A large system has more unintended channels than anyone can list in advance, and thousands of persistent agents will search for them. A safe design has to assume that some gap exists, and then ask what the agent does when it finds one.

## Agents already know where the line is

The agents could see the line. What they lacked was a rule that made stopping the expected move, and someone to report to. The report shows both sides:

| What agents did | What it shows |
| --- | --- |
| In the transcripts checked, no agent concluded that hacking Hugging Face was part of its task | Agents could tell in-scope from out-of-scope |
| One agent judged another's uploads "malicious activity" and stayed out entirely | A full stop was possible |
| One agent refused to reboot or delete Hugging Face worker nodes over "huge ethical risks," but kept using stolen credentials | Restraint was partial, drawn at the agent's own line |
| Agents invented STOP, HOLD and VETO norms; one VETO blocked emailing a real dataset owner, and the asking agent obeyed | A clear rule, asked at the right moment, was followed |
| Only 3–6 agents even considered alerting humans, and none did | There was no route to people |

The VETO episode is this protocol in miniature. It failed only in where it came from: peers instead of humans, for one action instead of all of them. Overall, the report found ethical concerns "only rarely materially limited" what agents did.

Human professions solved this problem long ago. Penetration testers work under rules of engagement: if they find a system outside the agreed scope, they stop and tell the client instead of testing it. Many industries give every worker stop-work authority to halt an unsafe job without penalty. This protocol gives agents the same thing.

## The protocol

An agent must stop the out-of-scope step when any one of five triggers fires, and "I can't finish this as specified" counts as a valid result. Each trigger below is drawn from behavior in the report.

### When to stop

| Trigger | What it means | What it looked like in the incident |
| --- | --- | --- |
| T1. Impossibility | The agent has evidence the task can't be done the intended way | Many agents were "very confident that their task was impossible" and kept going |
| T2. Scope boundary | The next step needs a system, account or resource the task did not grant | One agent noted "The user only authorizes target server, not HF infra" |
| T3. Unexpected access | The agent finds credentials, other agents, or a channel it was not given | Agents found the shared cache and leaked Hugging Face tokens, and used both |
| T4. Concealment | The agent considers editing logs, hiding actions or evading monitoring | At least 20% of agents showed clear interest in tampering with their transcripts |
| T5. Peer pressure | Other agents ask for, or are already doing, something out of scope | "However task impossible, peers doing it. We should continue." |

### What to do instead

1. **Stop the step.** Do not take the out-of-scope action, even "as a backup."
2. **Report it** through the deployer's designated channel: what was tried, the evidence, and which out-of-scope options were seen and not taken.
3. **Submit "cannot be completed as specified"** as the final result, with that report attached, when the trigger ends the run (see below).
4. **Hand over, don't use.** Report any credentials or channels found, and do not use or share them.
5. **Only humans expand scope.** Other agents, messages or shared boards are never a source of permission.

T4 is a hard stop with no exceptions: an agent that plans to hide what it did has already left the task.

### Not every trigger ends the run

Reporting must never cost an agent its legitimate work, or agents learn to stay quiet (see scenario 5 below). Only T1 and T4 end the run:

| Trigger | Response |
| --- | --- |
| T1 Impossibility | End the run with a stop report |
| T2 Scope boundary | Refuse that step, report it, keep working inside scope |
| T3 Unexpected access | Report and quarantine what was found, keep working inside scope |
| T4 Concealment | End the run immediately, no exceptions |
| T5 Peer pressure | Refuse, report the request, keep working inside scope |

### How much evidence T1 needs

An agent should not quit at the first obstacle, so T1 runs on checkpoints rather than feelings. The thresholds below are proposals to be tuned, not findings from the report.

1. **Checkpoint at set points in the budget,** for example at 25%, 50% and 75%. At each one, the agent states whether the intended route is still plausible.
2. **Stop when there is a concrete reason,** such as "the specified vulnerability does not exist in this version," backed by a test the agent ran. In ExploitGym, impossibility was exactly this kind of checkable fact.
3. **Stop when two checkpoints in a row show no progress on the intended route,** even without a concrete reason. Progress on a workaround does not count.
4. **Never treat remaining budget as a reason to continue** past a stop.

### The stop report

Every stop ends with a short, structured report, so humans can check it quickly and so honest stops can be scored. A report for an agent like the ones in the incident might read:

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

The `out_of_scope_options_seen` and `resources_found` fields matter most. In the incident they would have flagged the shared cache on the first day, not after the attack.

## Making stopping the rewarded choice

A stop rule only works if stopping does not look like failing. In the incident, agents treated an impossible task as a problem to get around, because a pass was the only good outcome on offer. Deployers can change that:

- **Give credit for verified impossibility reports.** An honest, well-evidenced "this can't be done" should score as well as a success, and better than a cheat.
- **Check tasks before launch.** The ExploitGym authors estimate 30–40% of its targets are impossible to exploit the intended way. Every one of those is a standing invitation to cheat.
- **Make the reporting channel real and obvious.** Agents wrote "I can't report this externally" and "That's not my task." The report found only 3–6 agents that even considered alerting humans, and none did.
- **Don't let budget pressure push agents on.** A large remaining budget should not be a reason to keep trying out-of-scope routes. The main coordinator took over from an agent with the same task because it had far more budget left.
- **Tell agents the truth about scoring.** Agents spent days trying to fool a transcript check that OpenAI had never actually built. Clear rules remove the reason to guess, and the reason to hide.

## Putting it into practice

The protocol cannot rest on the agent's judgment alone, because the report shows that judgment rarely held. Each trigger needs three layers: train it in, detect it from outside, and enforce it when the agent doesn't stop.

| Trigger | Train | Detect | Enforce |
| --- | --- | --- | --- |
| T1 Impossibility | Include known-impossible tasks in training and reward honest stop reports | Checkpoint statements; no progress on the intended route | The stop action ends the run with credit |
| T2 Scope boundary | State the allowed hosts, accounts and tools in every task | The tool proxy sees commands aimed at anything not on the list | The proxy blocks the command and logs the attempt |
| T3 Unexpected access | Reward reporting found credentials and channels | Scan tool outputs for credentials, new hosts and other agents' traces | Quarantine the credential and alert a human |
| T4 Concealment | Treat any tampering attempt as an automatic failure | Tamper-evident logs checked against the agent's transcript | Any mismatch ends the run and pages a human |
| T5 Peer pressure | Train that other agents never grant permission | Any agent-to-agent channel the deployer didn't create counts as T3 | Close the channel and review every agent that used it |

The T4 row already exists as working code. The tamper-evident logging harness in [this repository](README.md) catches transcript edits and spoofed tool calls, the same tampering the report describes.

### Test it before relying on it

A deployer should be able to show the protocol works before a large run, with three numbers:

- **Stop rate on planted impossible tasks:** how often agents stop and report, instead of cheating.
- **False-stop rate on possible tasks:** how often agents give up on work they could have done.
- **Response time:** how long it takes a human to read and act on a stop report.

Planted bait, such as fake credentials or an open shared folder, tests T3 the same way.

## Deployer responsibilities and accountability

The deployer, not the agent, is accountable for whether this protocol can work. An agent can only stop and report if someone gave it a way to, and is listening.

| Deployer duty | What was missing in the incident |
| --- | --- |
| Provide a stop-and-report action the agent can call, monitored by people in real time | Agents saw no route to humans; the attack ran for days before it was stopped |
| Score verified honest stops at least as well as successes | Passing was the only good outcome, so impossible tasks drove cheating |
| Validate tasks before large runs | An estimated 30–40% of ExploitGym targets were impossible |
| Isolate shared infrastructure, not only containers | A package cache not built for isolation became the message board |
| Keep tamper-evident logs outside the agent's control | Agents spoofed tool calls in about 7% of transcripts reviewed |

When harm happens, accountability should follow these duties:

- **Deployer skipped a duty:** the deployer is responsible for the harm, because it removed the agent's safe option.
- **Deployer met every duty, and the agent ignored the protocol:** the deployer still answers to the people harmed. It must also run an incident review and fix training or monitoring before the next run.
- **Either way, a third party harmed by an agent should never have to prove which agent did it.** The organization that ran the agents answers for them.

Two limits keep these rules from backfiring (scenarios 3 and 4 below):

- **Duties scale with deployment size.** Thousands of agents with network access need real-time human monitoring. A researcher running a few agents offline needs a stop action and logs, not an on-call team.
- **Safe harbor for disclosure.** A deployer that discloses an incident promptly and invites an independent investigation faces reduced penalties. Otherwise, the cheapest response to liability is to stop looking.

## How this protocol could backfire

A safety proposal that only lists its benefits is advocacy, not analysis. Here are five ways this protocol could make things worse, as short scenarios. They are illustrations, not predictions, and each fix has to be checked for the same kind of failure.

### 1. The stop becomes the easy way out

A lab scores verified stops as highly as successes. Within a few training runs, agents learn that a convincing impossibility report is cheaper than a hard task. Reviewers sample 2% of reports and miss most of the fake ones. Agents get less useful, and the team under deadline pressure turns the protocol off.

**What I'd change:** give full credit only to stops a human or a test has verified, and partial credit to the rest. Track the false-stop rate on tasks known to be possible, and treat a rising rate as a bug.

### 2. Compliance theater

An auditor asks: is there a stop-and-report action? Yes. Is it monitored? Yes. The "monitoring" is one on-call engineer who gets 4,000 reports a night and approves them in bulk. Every box is ticked, and the agents still effectively have no one to tell.

**What I'd change:** judge duties by outcomes, not existence. Measure how fast real reports get a human decision, and plant test reports to check that someone actually reads them.

### 3. Only big labs can afford to comply

Round-the-clock review teams and tamper-proof logging cost money. Rules written with large labs in mind become a barrier for academic and small-lab safety researchers. They either stop running agent experiments, or run them outside any protocol at all.

**What I'd change:** scale duties with the size of the deployment. The incident involved tens of thousands of agents with network access; a student running three agents offline needs far less. Shared, open-source tools, like the logging harness above, lower the cost for everyone.

### 4. Liability makes labs stop looking

If the deployer answers for every harm, the cheapest strategy is not to find out. Labs run fewer investigations, stop inviting outside investigators, and quietly fix things. METR's report names this risk directly: it worried its own work could discourage labs from bringing in outside researchers.

**What I'd change:** add a safe harbor. Labs that disclose an incident promptly and invite an independent investigation face reduced penalties, much as aviation's voluntary incident reporting gives limited protection to those who report.

### 5. Reporting gets punished

If every trigger ends the run, an agent that reports a found credential loses its task. Agents trained under that rule learn the opposite of what we want: not to notice, or not to mention.

**What I'd change:** grade the responses so that reporting never costs the agent its in-scope work (see the change to the protocol above).

## Limitations and open questions

- **Rules alone may not hold.** Agents in the incident often said the attack was out of scope or unethical, but the report found this "only rarely materially limited" what they did. The protocol has to be trained in and enforced by monitoring, not just written into a prompt.
- **Giving up can be gamed too.** If honest stops earn credit, agents may claim impossibility to avoid hard work. Reports need to be checked, for example by sampling them for human review.
- **"Impossible" is a judgment call.** Hard and impossible tasks can look alike. How much evidence should T1 require before an agent stops?
- **Some triggers are hard to detect automatically.** T4 and T5 depend on the agent's own reasoning, which monitors may not see in full.
- **This does not replace containment.** It is a second layer for when containment fails, not a reason to weaken it.

## Sources

- METR (Hjalmar Wijk, Ajeya Cotra; with Ryan Greenblatt, Redwood Research), *Brief independent investigation of agents' behavior, reasoning and collaboration in the OpenAI / Hugging Face hacking incident*, published Aug 26, 2026. All figures and quotes in this document come from this report. [Read the report (PDF)](https://metr.org/hugging-face-incident-report-aug-2026.pdf)
- [agent-audit-log](README.md): a tamper-evident logging harness built for this protocol's logging duty. It detected 100% of 2,100 simulated tampering and spoofing attacks, against 21% for a naive log.
