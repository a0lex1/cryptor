from typing import Callable, Any, Tuple, List

# ReplerHandler(s) return(s) FnCreateResult objects that used to both first instantiate and further duplicate the result
FnCreateResult = Callable[[], Any]

#                         args       piece_loc        (ret)
ReplerHandler = Callable[[List[str], Tuple[int,int]], FnCreateResult]

