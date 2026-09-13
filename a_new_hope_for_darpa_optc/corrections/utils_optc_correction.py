import json
import gzip
import json
from itertools import islice
from typing import Any, Dict, Iterator, List, Optional, Union



def get_iterator(
    path: str,
    batch_size: Optional[int] = None,
    raw_data: bool = False,
    fields: Optional[List[str]] = None,
    drop_last_batch: bool = True,
) -> Union[Iterator[Dict], Iterator[List[Dict]], Iterator[bytes],
           Iterator[List[bytes]]]:
    '''
    Returns iterator of a json data from path of a json.gz file.

    If batch_size is None, each object of the iterator is a dictionary.
    Otherwise, each object of the iterator is a list of dictionaries.

    Batch mode: If drop_last_batch is True (default),
                last batch (with size < batch_size) is dropped.
                Else: last batch is returned.

    If fields is True, selects only fields in that list in the returned dictionaries.

    If raw_data is True, objects are not converted as dictionaries but left as bytes strings.
    If raw_data is True, fields is ignored.
    '''
    current_batch = []
    with gzip.open(path) as f:
        for i, content in enumerate(f):
            if not raw_data:
                # Loading line as json
                try:
                    content = json.loads(content)
                except Exception as e:
                    print('Warning: line not understood in file', path,
                          ', line', i, ':', content, e)
                    break  # Early stop because exception is not normal
                if fields is not None:
                    # Extracting relevant fields from dictionary
                    content = {k: content[k] for k in fields if k in content}
            if batch_size is None:
                # No batch -> yield object
                yield content
            else:
                # Batch mode -> add to current batch, yield batch if needed
                current_batch.append(content)
                if len(current_batch) == batch_size:
                    yield current_batch
                    current_batch = []
        if not drop_last_batch and current_batch:
            # yield last batch
            yield current_batch


def get_data(iterator: Iterator[Any], n: Optional[int] = None) -> List[Any]:
    '''
    Returns n first data of iterator as list.
    If n is None: returns all iterator data as list.
    '''
    if n is not None:
        iterator = islice(iterator, n)
    return list(iterator)

def write_batch(filename: str, batch: Iterator[Dict], append=False) -> None:
    '''
    Writes a batch of dictionaries into filename, in .json.gz format.
    If append is True, appends to file. Otherwise, erases file before writing.
    '''
    mode = 'a' if append else 'w'
    with gzip.open(filename, mode) as f:
        for d in batch:
            f.write((json.dumps(d) + '\n').encode('utf8'))
