"use client";

import { useCallback, useEffect, useState } from "react";

import { apiRequest } from "@/lib/api/client";

export function useApiQuery<T>(path: string) {
  const [result, setResult] = useState<{
    key: string;
    data: T | null;
    error: string | null;
  }>({ key: "", data: null, error: null });
  const [version, setVersion] = useState(0);
  const requestKey = `${path}:${version}`;

  const reload = useCallback(() => setVersion((value) => value + 1), []);

  useEffect(() => {
    let active = true;
    apiRequest<T>(path)
      .then((value) => {
        if (active) setResult({ key: requestKey, data: value, error: null });
      })
      .catch((reason: unknown) => {
        if (active) setResult({
          key: requestKey,
          data: null,
          error: reason instanceof Error ? reason.message : "Something went wrong.",
        });
      });
    return () => { active = false; };
  }, [path, requestKey]);

  return {
    data: result.key === requestKey ? result.data : null,
    error: result.key === requestKey ? result.error : null,
    loading: result.key !== requestKey,
    reload,
  };
}
