# ATLAS(v2)

Ground truth labels for the ATLASv2 attack engagement.

## Using ATLASv2

While there are ten attacks in ATLASv2, *all attacks are highly redundant,* creating the potential for the dataset to be used incorrectly in anomaly detection tasks. Training on any of the attack data is equivalent to training on test data, as shown below:

We have provided the attack procedures from the original ATLAS dataset in the attack_descriptions folder. Attacks S1 - S4 are comprised of the following steps:

![atlas_steps_s1-4](imgs/atlas_steps_s1-4.png)

In Step 2, S1 and S2 use a Word vulnerability while S3 and S4 use a flash vulnerability instead. This means that, for each attack, three other attacks are highly similar (4 of 5 steps are the same) and one attack is nearly identical (same attack vector in step 2):

![atlas_diversity_s1-4](imgs/atlas_diversity_s1-4.png)

Attacks M1-M6 are continuations of S1-S4 that spread to a second machine. Here are the new steps introduced to the singlehost procedure:

![atlas_steps_m1-6](imgs/atlas_steps_m1-6.png)

Like the singlehost attacks, the multihost attacks only meaningfully vary in step two, with 7 of 8 highly similar steps in the attack chain:

![atlas_diversity_m1-6](imgs/atlas_diversity_m1-6.png)

Used correctly, it is appropriate (and perhaps even desirable!) to test on subtle variations of the same attack chain. 
However, please be wary about the potential to misinterpret models trained on this attack data.
The original ATLAS paper used these attacks to demonstrate the ability to recognize patterns from previously viewed attacks,
  making their interpretation of the results valid.
If the same leave-one-attack-out procedure was used to evaluate a generic intrustion detection model, 
  reporting the results without sufficient context would be disengenuous.

## Visualizations

To provide some intuition as to what is happening in the attacks, we provide visualizations for each. Nodes the we identified as root causes are colored red, while nodes that we identified as attack impacts are colored green. Processes that make up the attack chain are colored yellow. We have simplified the graphs for visualization purposes (deduplicated edges, merged nodes with the same label, merged multi-process programs into a single node). Note that these simplifications are for visualization only; the labeling methodology was performed on the raw graph.

### Multihost Attack M1

*Host 1*

![H1-M1](imgs/h1-m1.png)

*Host 2*

![H2-M1](imgs/h2-m1.png)

Note that one remote host (the IP address shaded in yellow) is wrongfully implicated in this attack.  This is a result of the background activities conducted by a second experimenter during the attack engagement. It does not effect the processes identified in the attack chain.

### Multihost Attack M2

*Host 1*

![H1-M2](imgs/h1-m2.png)

*Host 2*

![H2-M2](imgs/h2-m2.png)

Note that many remote hosts (the IP addresses shaded in yellow) are wrongfully implicated in this attack.  This is a result of the background activities conducted by a second experimenter during the attack engagement. It does not effect the processes identified in the attack chain.

### Multihost Attack M3

*Host 1**

![H1-M3](imgs/h1-m3.png)

*Host 2*

![H2-M3](imgs/h2-m3.png)

Note that two remote hosts (the IP addresses shaded in yellow) are wrongfully implicated in this attack.  This is a result of the background activities conducted by a second experimenter during the attack engagement. It does not effect the processes identified in the attack chain.

### Multihost Attack M4

*Host 1*

![H1-M4](imgs/h1-m4.png)

*Host 2*

![H2-M4](imgs/h2-m4.png)

Note that one remote host (the IP address shaded in yellow) is wrongfully implicated in this attack.  This is a result of the background activities conducted by a second experimenter during the attack engagement. It does not effect the processes identified in the attack chain.

### Multihost Attack M5

*Host 1*

![H1-M5](imgs/h1-m5.png)

*Host 2*

![H2-M5](imgs/h2-m5.png)

Note that one remote host (the IP address shaded in yellow) is wrongfully implicated in this attack.  This is a result of the background activities conducted by a second experimenter during the attack engagement. It does not effect the processes identified in the attack chain.

### Multihost Attack M6

*Host 1*

![H1-M6](imgs/h1-m6.png)

*Host 2*

![H2-M6](imgs/h2-m6.png)

Note that five remote hosts (the IP addresses shaded in yellow) are wrongfully implicated in this attack.  This is a result of the background activities conducted by a second experimenter during the attack engagement. It does not effect the processes identified in the attack chain.

### Singlehost Attack S1

*Host 1*

![H1-S6](imgs/h1-s1.png)

### Singlehost Attack S2

*Host 1*

![H1-S2](imgs/h1-s2.png)

### Singlehost Attack S3

*Host 1*

![H1-S3](imgs/h1-s3.png)

### Singlehost Attack S4

*Host 1*

![H1-S4](imgs/h1-s4.png)

## Notes

- Host 1's IP address in the Host 2 logs appears as 10.193.242.113.
- The attacker's IP address in either log appears as 10.193.66.115.
- The malicious "email attachments" (`msf.rtf`, `msf.doc`) were downloaded from a GMail session on Firefox and were then detonated from the Downloads folder; there is no mail client activity in the attack chains.
