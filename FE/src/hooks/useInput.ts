import React, { useState } from 'react';
import { useSearchParams } from 'react-router-dom';

const useInput = (validateFn: (value: string) => boolean) => {
  const [inputValue, setInputValue] = useState('');
  const [isValid, setIsValid] = useState(false);
  const valueChangeHandler = (event: React.ChangeEvent<HTMLInputElement>) => {
    setInputValue(event.target.value);
    setIsValid(validateFn(event.target.value));
  };

  const reset = () => {
    setInputValue('');
  };

  return {
    value: inputValue,
    isValid,
    valueChangeHandler,
    reset,
  };
};

export default useInput;
