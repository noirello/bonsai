import bonsai

class LDAPValueList(list):
    
    __slots__ = ("__deleted", "__added", "__status")
    
    def __init__(self, items=None):
        super().__init__()
        self.__added = []
        self.__deleted = []
        self.__status = 0
        if items:
            for item in items:
                self.append(item)
    
    @staticmethod
    def __balance(lst1, lst2, value):
        """
        Balancing between the two list (__added, __deleted),
        make sure the same element is not in both lists.
        """
        try:
            lst1.remove(value)
        except ValueError:
            lst2.append(value)
    
    def _append_unchecked(self, value):
        super().append(value)
            
    def __contains__(self, item):
        return bonsai._unique_contains(self, item)[0]
    
    def __delitem__(self, idx:int):
        old_value = super().__getitem__(idx)
        if type(idx) == slice:
            for item in old_value:
                self.__balance(self.__added, self.__deleted, item)
        else:
            self.__balance(self.__added, self.__deleted, old_value)
        super().__delitem__(idx)
    
    def __setitem__(self, idx:int, value):
        old_value = self[idx]
        if type(idx) == slice:
            for item in value:
                if item in self:
                    raise ValueError("%r is already in the list." % item)
            for item in old_value:
                self.__balance(self.__added, self.__deleted, item)
            for item in value:
                self.__balance(self.__deleted, self.__added, item)
        else:
            if value in self:
                raise ValueError("%r is already in the list." % value)
            self.__balance(self.__added, self.__deleted, old_value)
            self.__balance(self.__deleted, self.__added, value)
        super().__setitem__(idx, value)
    
    def append(self, item):
        """
        Add a unique item to the end of the list. 
        
        :param item: New item.
        :raises ValueError: if the `item` is not unique. 
        """
        
        if item in self:
            raise ValueError("%r is already in the list." % item)
        self.__balance(self.__deleted, self.__added, item)
        super().append(item)
        
    def extend(self, items):
        """
        Extend the list by appending all the items in the given list.
        All element in `items` must be unqiue and also not represented
        in the list.
        
        :param items: List of new items.
        :raises ValueError: if any of the items is already in the list.
        """
        for item in items:
            if item in self:
                raise ValueError("%r is already in the list." % item)
        for item in items:
            self.__balance(self.__deleted, self.__added, item)
        super().extend(items)
    
    def insert(self, idx:int, value):
        """
        Insert a unique item at a given position. 
        
        :param int idx: the position.
        :param value: the new item.
        :raises ValueError: if the `item` is not unique. 
        """
        if value in self:
            raise ValueError("%r is already in the list." % value)
        self.__balance(self.__deleted, self.__added, value)
        super().insert(idx, value)
    
    def remove(self, value):
        """
        Remove the first item from the list whose value is `value`.
        
        :param value: the item to be removed.
        :raises ValueError: if `value` is not int the list.
        """
        contain, obj = bonsai._unique_contains(self, value)
        if not contain:
            raise ValueError("%r is not in the list." % value)
        super().remove(obj)
        self.__balance(self.__added, self.__deleted, obj)
    
    def pop(self, idx: int=-1):
        """
        Remove the item at the given position in the list, and return it.
        If no index is specified, pop() removes and returns the last item
        in the list.
        
        :param int idx: optional index.
        """
        value = super().pop(idx)
        self.__balance(self.__added, self.__deleted, value)
        return value
    
    def clear(self):
        """ Remove all items from the list. """
        del self[:]
    
    @property
    def status(self):
        return self.__status

    @status.setter
    def status(self, value):
        if (type) != int:
            raise TypeError("Status must be int.")
        if value > -1 and value < 3:
            self.__status = value
        else:
            raise ValueError("Status must be between 0 and 2")
