'use client';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { api } from '@/lib/api-client';

export function useAlerts(params?: { severity?: string; status?: string; limit?: number }) {
  return useQuery({
    queryKey: ['alerts', params],
    queryFn: () => api.getAlerts(params),
    refetchInterval: 10000,
  });
}

export function useAlert(id: string) {
  return useQuery({
    queryKey: ['alert', id],
    queryFn: () => api.getAlert(id),
    refetchInterval: 15000,
  });
}

export function useUpdateAlertStatus() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ id, status, analyst }: { id: string; status: string; analyst: string }) =>
      api.updateAlertStatus(id, status, analyst),
    onSuccess: (_, vars) => {
      qc.invalidateQueries({ queryKey: ['alert', vars.id] });
      qc.invalidateQueries({ queryKey: ['alerts'] });
    },
  });
}

export function useAddNote() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ id, note, analyst, action }: { id: string; note: string; analyst: string; action?: string }) =>
      api.addNote(id, note, analyst, action),
    onSuccess: (_, vars) => {
      qc.invalidateQueries({ queryKey: ['alert', vars.id] });
    },
  });
}
