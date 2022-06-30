import React, { useState, useRef, useEffect } from 'react';

const useClose = () => {
  const [isOpen, setIsOpen] = useState(false);

  const popupRef = useRef<HTMLDivElement>(null);

  const closeHandler = (e: MouseEvent) => {
    if (!popupRef.current?.contains(e.target as Node)) {
      setIsOpen(false);
    }
  };

  useEffect(() => {
    if (!isOpen) return;
    document.addEventListener('click', closeHandler);
    return () => {
      document.removeEventListener('click', closeHandler);
    };
  }, [isOpen]);

  return {
    popupRef,
    isOpen,
    setIsOpen,
  };
};

export default useClose;
