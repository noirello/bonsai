import bonsai

class LDAPValueList(list):
    """
    Modified list that tracks added and deleted values. It also conatains
    only unique elements. The elements are compared to their lower-cased
    string representations.

    A new LDAPValueList can be created optionally from an existing
    sequence object.

    :param items: a sequence object.
    :raises ValueError: if `items` has a non-unique element.
    """
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

    @property
    def _status_dict(self):
        return {"@status": self.__status,
                "@added": self.__added.copy(),
                "@deleted": self.__deleted.copy()}

    @_status_dict.setter
    def _status_dict(self, value):
        raise TypeError("Can not change _status_dict")

    def __contains__(self, item):
        return bonsai._unique_contains(self, item)[0]

    def __delitem__(self, idx: int):
        old_value = super().__getitem__(idx)
        if type(idx) == slice:
            for item in old_value:
                self.__balance(self.__added, self.__deleted, item)
        else:
            self.__balance(self.__added, self.__deleted, old_value)
        super().__delitem__(idx)

    def __mul__(self, value):
        raise TypeError("Cannot multiple LDAPValueList.")

    def __add__(self, other):
        if type(other) != list and type(other) != LDAPValueList:
            raise TypeError("Can only concatenate list and LDAPValueList.")
        new_list = self.copy()
        new_list.extend(other)
        return new_list

    def __iadd__(self, other):
        if type(other) != list and type(other) != LDAPValueList:
            raise TypeError("Can only concatenate list and LDAPValueList.")
        self.extend(other)
        return self

    def __setitem__(self, idx: int, value):
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
        Add a unique item to the end of the LDAPValueList.

        :param item: New item.
        :raises ValueError: if the `item` is not unique.
        """

        if item in self:
            raise ValueError("%r is already in the list." % item)
        self.__balance(self.__deleted, self.__added, item)
        self.__status = 1
        super().append(item)

    def extend(self, items):
        """
        Extend the LDAPValueList by appending all the items in the given
        list. All element in `items` must be unqiue and also not
        represented in the LDAPValueList.

        :param items: List of new items.
        :raises ValueError: if any of the items is already in the list.
        """
        for item in items:
            if item in self:
                raise ValueError("%r is already in the list." % item)
        for item in items:
            self.__balance(self.__deleted, self.__added, item)
        self.__status = 1
        super().extend(items)

    def insert(self, idx: int, value):
        """
        Insert a unique item at a given position.

        :param int idx: the position.
        :param value: the new item.
        :raises ValueError: if the `item` is not unique.
        """
        if value in self:
            raise ValueError("%r is already in the list." % value)
        self.__balance(self.__deleted, self.__added, value)
        self.__status = 1
        super().insert(idx, value)

    def remove(self, value):
        """
        Remove the first item from the LDAPValueList whose value is `value`.

        :param value: the item to be removed.
        :raises ValueError: if `value` is not int the list.
        """
        contain, obj = bonsai._unique_contains(self, value)
        if not contain:
            raise ValueError("%r is not in the list." % value)
        super().remove(obj)
        self.__status = 1
        self.__balance(self.__added, self.__deleted, obj)

    def pop(self, idx: int=-1):
        """
        Remove the item at the given position in the LDAPValueList, and
        return it. If no index is specified, pop() removes and returns the
        last item in the list.
        
        :param int idx: optional index.
        """
        value = super().pop(idx)
        self.__balance(self.__added, self.__deleted, value)
        self.__status = 1
        return value

    def clear(self):
        """ Remove all items from the LDAPValueList. """
        del self[:]

    def copy(self):
        """
        Return a shallow copy of the LDAPValueList. This includes
        the status and the previously added and deleted items.

        :rtype: LDAPValueList
        :return: The copy of the LDAPValueList.
        """
        new_list = LDAPValueList()
        for item in self:
            new_list._append_unchecked(item)
        new_list.__added = self.__added.copy()
        new_list.__deleted = self.__deleted.copy()
        new_list.__status = self.__status
        return new_list

    @property
    def status(self):
        """
        The status of the LDAPValueList. The status can be:
            - 0: unchanged.
            - 1: added or deleted item to list.
            - 2: replaced the entire list.
        """
        return self.__status

    @status.setter
    def status(self, value):
        if type(value) != int:
            raise TypeError("Status must be int.")
        if value > -1 and value < 3:
            self.__status = value
        else:
            raise ValueError("Status must be between 0 and 2")
