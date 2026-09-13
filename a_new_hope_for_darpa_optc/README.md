# A New Hope for Darpa OpTC

This repository is associated with the article [A New Hope For Darpa
Optc](https://inria.hal.science/hal-05474126v1/). It contains three directories
with the code used for the corrections of DARPA OpTC, for the experiments of the paper and for the labeling of the host and network events.

## Darpa OpTC

[DARPA OpTC](https://github.com/FiveDirections/OpTC-data) is a dataset designed
to evaluate intrusion detection systems. It contains host and network events for
an IT system containing 1000 Windows hosts. Three different APT attacks are
launched against the IT system on the last three days of the dataset. While
being very interesting by the the size of the IT system and the nature of the
attacks in the dataset, DARPA OpTC suffers from two drawbacks: the lack of an
official labelling of the events and some errors in the host data.

In this work, we provide labels for the host and network data and fix as much as
possible the host events.

There is a dedicated website for the [project](https://correctedoptc.inria.fr/). The corrected version of the dataset is available at the [entrepot of the French Ministry of Research](https://entrepot.recherche.data.gouv.fr/dataset.xhtml?persistentId=doi:10.57745/UXCWOC). 

## Citing this work

If you use this work, plese cite:
```
@inproceedings{majorczyk:hal-05474126,
  TITLE = {{A New Hope for DARPA OpTC}},
  AUTHOR = {Majorczyk, Fr{\'e}d{\'e}ric and Pilastre, Barbara and Dijoud, Fanny},
  URL = {https://inria.hal.science/hal-05474126},
  BOOKTITLE = {{CSET 2025 - Cyber Security Experimentation and Test at ACSAC 2025 International Workshops}},
  ADDRESS = {Honolulu, United States},
  YEAR = {2025},
  MONTH = Dec,
  KEYWORDS = {Dataset curation ; Dataset ; Intrusion Detection},
  PDF = {https://inria.hal.science/hal-05474126v1/file/cset-2025.pdf},
  HAL_ID = {hal-05474126},
  HAL_VERSION = {v1},
}
```
