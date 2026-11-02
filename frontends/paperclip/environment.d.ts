/// <reference types="vite/client" />
// Type-only seam for the upstream heartbeat API. This frontend does not expose
// runtime question submission or provide an adapter-utils implementation.
declare module '@paperclipai/adapter-utils' {
  export interface PaperclipQuestionResponse {
    schema: 'paperclip.question_response.v1';
    answers: Record<string, { selectedOptionIds?: string[]; text?: string; customText?: string }>;
  }
}
