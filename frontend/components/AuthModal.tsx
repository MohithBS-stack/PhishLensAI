"use client";

import React, { useState, useEffect, useRef } from "react";
import { useAuth } from "@/lib/auth-context";
import {
  Shield,
  X,
  Mail,
  Lock,
  User as UserIcon,
  Eye,
  EyeOff,
  AlertCircle,
  CheckCircle2,
  KeyRound,
  ArrowRight,
  Terminal,
} from "lucide-react";

export type AuthMode = "login" | "register";

interface AuthModalProps {
  isOpen: boolean;
  onClose: () => void;
  initialMode?: AuthMode;
}

export const AuthModal: React.FC<AuthModalProps> = ({
  isOpen,
  onClose,
  initialMode = "login",
}) => {
  const { login, register, isLoading, error: authError, clearError } = useAuth();

  const [mode, setMode] = useState<AuthMode>(initialMode);
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [fullName, setFullName] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [showConfirmPassword, setShowConfirmPassword] = useState(false);
  const [clientErrors, setClientErrors] = useState<Record<string, string>>({});
  const [successMessage, setSuccessMessage] = useState<string | null>(null);

  const modalRef = useRef<HTMLDivElement>(null);
  const emailInputRef = useRef<HTMLInputElement>(null);

  // Sync mode when initialMode changes or modal opens
  useEffect(() => {
    if (isOpen) {
      setMode(initialMode);
      setClientErrors({});
      setSuccessMessage(null);
      clearError();
      // Focus first input
      setTimeout(() => {
        emailInputRef.current?.focus();
      }, 50);
    }
  }, [isOpen, initialMode, clearError]);

  // Handle ESC key to close
  useEffect(() => {
    if (!isOpen) return;

    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === "Escape") {
        onClose();
      }
    };

    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, [isOpen, onClose]);

  if (!isOpen) return null;

  const validateForm = (): boolean => {
    const errors: Record<string, string> = {};

    const cleanEmail = email.trim();
    if (!cleanEmail) {
      errors.email = "Email address is required.";
    } else if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(cleanEmail)) {
      errors.email = "Please enter a valid email address (e.g., analyst@security.org).";
    }

    if (!password) {
      errors.password = "Password is required.";
    } else if (password.length < 8) {
      errors.password = "Password must be at least 8 characters.";
    } else if (password.length > 128) {
      errors.password = "Password cannot exceed 128 characters.";
    }

    if (mode === "register") {
      if (!confirmPassword) {
        errors.confirmPassword = "Confirming your password is required.";
      } else if (password !== confirmPassword) {
        errors.confirmPassword = "Passwords do not match.";
      }
    }

    setClientErrors(errors);
    return Object.keys(errors).length === 0;
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    clearError();
    setSuccessMessage(null);

    if (!validateForm()) {
      return;
    }

    try {
      if (mode === "login") {
        await login({ email: email.trim(), password });
        setSuccessMessage("Authentication verified. Loading session...");
        setTimeout(() => {
          onClose();
        }, 600);
      } else {
        await register({
          email: email.trim(),
          password,
          full_name: fullName.trim() || undefined,
        });
        setSuccessMessage("Operator account created. Session established.");
        setTimeout(() => {
          onClose();
        }, 600);
      }
    } catch {
      // Error handled by AuthContext state
    }
  };

  const handleTabSwitch = (newMode: AuthMode) => {
    setMode(newMode);
    setClientErrors({});
    clearError();
    setSuccessMessage(null);
  };

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center p-4 sm:p-6 bg-[#111215]/80 backdrop-blur-xs transition-opacity duration-200"
      onClick={(e) => {
        if (e.target === e.currentTarget) {
          onClose();
        }
      }}
      role="presentation"
    >
      <div
        ref={modalRef}
        role="dialog"
        aria-modal="true"
        aria-labelledby="auth-modal-title"
        aria-describedby="auth-modal-desc"
        className="w-full max-w-md bg-[#ffffff] border border-[#cfccc2] shadow-2xl relative flex flex-col overflow-hidden animate-in fade-in zoom-in-95 duration-150"
      >
        {/* Terminal Header Bar */}
        <div className="bg-[#111215] text-[#f6f5f0] px-4 py-3 border-b border-[#27282f] flex items-center justify-between">
          <div className="flex items-center gap-2">
            <div className="h-5 w-5 bg-[#ea4e1b] flex items-center justify-center text-[#111215]">
              <Shield className="w-3.5 h-3.5" strokeWidth={3} />
            </div>
            <span
              id="auth-modal-title"
              className="font-mono text-xs font-bold tracking-wider uppercase text-[#f6f5f0]"
            >
              PHISHLENS // {mode === "login" ? "OPERATOR AUTHENTICATION" : "ACCOUNT PROVISIONING"}
            </span>
          </div>

          <button
            onClick={onClose}
            className="text-[#9a9ca8] hover:text-[#f6f5f0] transition-colors p-1 cursor-pointer"
            aria-label="Close authentication dialog"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Mode Selector Tabs */}
        <div className="grid grid-cols-2 border-b border-[#e4e1d8] bg-[#faf9f5]">
          <button
            type="button"
            onClick={() => handleTabSwitch("login")}
            className={`py-2.5 text-xs font-mono tracking-wider uppercase font-semibold transition-colors cursor-pointer border-r border-[#e4e1d8] ${
              mode === "login"
                ? "bg-[#ffffff] text-[#121316] border-b-2 border-b-[#ea4e1b]"
                : "text-[#747782] hover:text-[#121316] hover:bg-[#f6f5f0]"
            }`}
          >
            SIGN IN
          </button>
          <button
            type="button"
            onClick={() => handleTabSwitch("register")}
            className={`py-2.5 text-xs font-mono tracking-wider uppercase font-semibold transition-colors cursor-pointer ${
              mode === "register"
                ? "bg-[#ffffff] text-[#121316] border-b-2 border-b-[#ea4e1b]"
                : "text-[#747782] hover:text-[#121316] hover:bg-[#f6f5f0]"
            }`}
          >
            REGISTER
          </button>
        </div>

        {/* Form Body */}
        <div className="p-6">
          <p id="auth-modal-desc" className="text-xs text-[#4d5058] mb-5 font-sans leading-relaxed">
            {mode === "login"
              ? "Authenticate your forensic operator identity to unlock persistent investigation telemetry and secure sessions."
              : "Provision a new forensic analyst account. Credentials are encrypted via Argon2id with rotating session keys."}
          </p>

          {/* Feedback Notices */}
          {successMessage && (
            <div
              role="status"
              aria-live="polite"
              className="mb-4 p-3 bg-[#e8f6ed] border border-[#a8dfba] text-xs font-mono text-[#185a30] flex items-center gap-2"
            >
              <CheckCircle2 className="w-4 h-4 text-[#1b7e41] shrink-0" />
              <span>{successMessage}</span>
            </div>
          )}

          {authError && (
            <div
              role="alert"
              aria-live="polite"
              className="mb-4 p-3 bg-[#fdf2f0] border border-[#f8aba6] text-xs font-mono text-[#a52a2a] flex items-start gap-2"
            >
              <AlertCircle className="w-4 h-4 text-[#ea4e1b] shrink-0 mt-0.5" />
              <div className="space-y-1">
                <span className="font-bold">ERROR:</span> <span>{authError}</span>
              </div>
            </div>
          )}

          <form onSubmit={handleSubmit} className="space-y-4" noValidate>
            {/* Full Name Field (Register Mode Only) */}
            {mode === "register" && (
              <div>
                <label
                  htmlFor="auth-fullname"
                  className="block text-[11px] font-mono tracking-wider text-[#4d5058] uppercase mb-1 font-semibold"
                >
                  Full Name / Operator Handle <span className="text-[#747782] font-normal">(Optional)</span>
                </label>
                <div className="relative">
                  <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none text-[#747782]">
                    <UserIcon className="w-4 h-4" />
                  </div>
                  <input
                    id="auth-fullname"
                    type="text"
                    value={fullName}
                    onChange={(e) => setFullName(e.target.value)}
                    disabled={isLoading}
                    placeholder="e.g. Dana Scully"
                    className="w-full pl-9 pr-3 py-2 bg-[#ffffff] border border-[#cfccc2] text-xs text-[#121316] font-sans placeholder-[#9a9ca8] focus:outline-hidden focus:border-[#ea4e1b] focus:ring-1 focus:ring-[#ea4e1b] transition-colors"
                  />
                </div>
              </div>
            )}

            {/* Email Field */}
            <div>
              <label
                htmlFor="auth-email"
                className="block text-[11px] font-mono tracking-wider text-[#4d5058] uppercase mb-1 font-semibold"
              >
                Email Address <span className="text-[#ea4e1b]">*</span>
              </label>
              <div className="relative">
                <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none text-[#747782]">
                  <Mail className="w-4 h-4" />
                </div>
                <input
                  ref={emailInputRef}
                  id="auth-email"
                  type="email"
                  value={email}
                  onChange={(e) => {
                    setEmail(e.target.value);
                    if (clientErrors.email) {
                      setClientErrors((prev) => ({ ...prev, email: "" }));
                    }
                  }}
                  disabled={isLoading}
                  autoComplete="email"
                  placeholder="analyst@domain.com"
                  aria-invalid={!!clientErrors.email}
                  aria-describedby={clientErrors.email ? "email-error" : undefined}
                  className={`w-full pl-9 pr-3 py-2 bg-[#ffffff] border text-xs text-[#121316] font-sans placeholder-[#9a9ca8] focus:outline-hidden transition-colors ${
                    clientErrors.email
                      ? "border-[#ea4e1b] focus:border-[#ea4e1b] focus:ring-1 focus:ring-[#ea4e1b]"
                      : "border-[#cfccc2] focus:border-[#ea4e1b] focus:ring-1 focus:ring-[#ea4e1b]"
                  }`}
                />
              </div>
              {clientErrors.email && (
                <p id="email-error" className="mt-1 text-[11px] font-mono text-[#ea4e1b] flex items-center gap-1">
                  <span>›</span> {clientErrors.email}
                </p>
              )}
            </div>

            {/* Password Field */}
            <div>
              <label
                htmlFor="auth-password"
                className="block text-[11px] font-mono tracking-wider text-[#4d5058] uppercase mb-1 font-semibold"
              >
                Password <span className="text-[#ea4e1b]">*</span>
              </label>
              <div className="relative">
                <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none text-[#747782]">
                  <Lock className="w-4 h-4" />
                </div>
                <input
                  id="auth-password"
                  type={showPassword ? "text" : "password"}
                  value={password}
                  onChange={(e) => {
                    setPassword(e.target.value);
                    if (clientErrors.password) {
                      setClientErrors((prev) => ({ ...prev, password: "" }));
                    }
                  }}
                  disabled={isLoading}
                  autoComplete={mode === "login" ? "current-password" : "new-password"}
                  placeholder={mode === "register" ? "Minimum 8 characters" : "••••••••"}
                  aria-invalid={!!clientErrors.password}
                  aria-describedby={clientErrors.password ? "password-error" : undefined}
                  className={`w-full pl-9 pr-10 py-2 bg-[#ffffff] border text-xs text-[#121316] font-sans placeholder-[#9a9ca8] focus:outline-hidden transition-colors ${
                    clientErrors.password
                      ? "border-[#ea4e1b] focus:border-[#ea4e1b] focus:ring-1 focus:ring-[#ea4e1b]"
                      : "border-[#cfccc2] focus:border-[#ea4e1b] focus:ring-1 focus:ring-[#ea4e1b]"
                  }`}
                />
                <button
                  type="button"
                  onClick={() => setShowPassword(!showPassword)}
                  disabled={isLoading}
                  className="absolute inset-y-0 right-0 pr-3 flex items-center text-[#747782] hover:text-[#121316] transition-colors cursor-pointer"
                  aria-label={showPassword ? "Hide password" : "Show password"}
                >
                  {showPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                </button>
              </div>
              {clientErrors.password && (
                <p id="password-error" className="mt-1 text-[11px] font-mono text-[#ea4e1b] flex items-center gap-1">
                  <span>›</span> {clientErrors.password}
                </p>
              )}
            </div>

            {/* Confirm Password Field (Register Mode Only) */}
            {mode === "register" && (
              <div>
                <label
                  htmlFor="auth-confirm-password"
                  className="block text-[11px] font-mono tracking-wider text-[#4d5058] uppercase mb-1 font-semibold"
                >
                  Confirm Password <span className="text-[#ea4e1b]">*</span>
                </label>
                <div className="relative">
                  <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none text-[#747782]">
                    <KeyRound className="w-4 h-4" />
                  </div>
                  <input
                    id="auth-confirm-password"
                    type={showConfirmPassword ? "text" : "password"}
                    value={confirmPassword}
                    onChange={(e) => {
                      setConfirmPassword(e.target.value);
                      if (clientErrors.confirmPassword) {
                        setClientErrors((prev) => ({ ...prev, confirmPassword: "" }));
                      }
                    }}
                    disabled={isLoading}
                    autoComplete="new-password"
                    placeholder="Repeat password"
                    aria-invalid={!!clientErrors.confirmPassword}
                    aria-describedby={clientErrors.confirmPassword ? "confirm-error" : undefined}
                    className={`w-full pl-9 pr-10 py-2 bg-[#ffffff] border text-xs text-[#121316] font-sans placeholder-[#9a9ca8] focus:outline-hidden transition-colors ${
                      clientErrors.confirmPassword
                        ? "border-[#ea4e1b] focus:border-[#ea4e1b] focus:ring-1 focus:ring-[#ea4e1b]"
                        : "border-[#cfccc2] focus:border-[#ea4e1b] focus:ring-1 focus:ring-[#ea4e1b]"
                    }`}
                  />
                  <button
                    type="button"
                    onClick={() => setShowConfirmPassword(!showConfirmPassword)}
                    disabled={isLoading}
                    className="absolute inset-y-0 right-0 pr-3 flex items-center text-[#747782] hover:text-[#121316] transition-colors cursor-pointer"
                    aria-label={showConfirmPassword ? "Hide password confirmation" : "Show password confirmation"}
                  >
                    {showConfirmPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                  </button>
                </div>
                {clientErrors.confirmPassword && (
                  <p id="confirm-error" className="mt-1 text-[11px] font-mono text-[#ea4e1b] flex items-center gap-1">
                    <span>›</span> {clientErrors.confirmPassword}
                  </p>
                )}
              </div>
            )}

            {/* Submit Action Button */}
            <div className="pt-2">
              <button
                type="submit"
                disabled={isLoading}
                className="w-full py-2.5 px-4 bg-[#111215] text-[#f6f5f0] text-xs font-mono font-bold tracking-wider uppercase flex items-center justify-center gap-2 hover:bg-[#27282f] active:bg-[#000000] disabled:bg-[#747782] disabled:cursor-not-allowed transition-colors cursor-pointer"
              >
                {isLoading ? (
                  <>
                    <div className="w-3.5 h-3.5 border-2 border-[#f6f5f0] border-t-transparent rounded-full animate-spin" />
                    <span>{mode === "login" ? "AUTHENTICATING..." : "PROVISIONING..."}</span>
                  </>
                ) : (
                  <>
                    <span>{mode === "login" ? "AUTHORIZE OPERATOR SESSION" : "PROVISION CREDENTIALS"}</span>
                    <ArrowRight className="w-3.5 h-3.5 text-[#ea4e1b]" />
                  </>
                )}
              </button>
            </div>
          </form>

          {/* Mode Switcher Footer */}
          <div className="mt-5 pt-4 border-t border-[#e4e1d8] flex items-center justify-between text-[11px] font-mono text-[#747782]">
            <span>
              {mode === "login" ? "Need operator credentials?" : "Already registered?"}
            </span>
            <button
              type="button"
              onClick={() => handleTabSwitch(mode === "login" ? "register" : "login")}
              disabled={isLoading}
              className="text-[#ea4e1b] hover:text-[#d54212] font-semibold uppercase tracking-wider underline cursor-pointer"
            >
              {mode === "login" ? "CREATE ACCOUNT" : "SIGN IN INSTEAD"}
            </button>
          </div>
        </div>

        {/* Security & Architecture Telemetry Footer */}
        <div className="bg-[#faf9f5] border-t border-[#e4e1d8] px-4 py-2 flex items-center justify-between text-[10px] font-mono text-[#747782]">
          <div className="flex items-center gap-1.5">
            <Terminal className="w-3 h-3 text-[#ea4e1b]" />
            <span>SESSION: MEMORY TOKEN + HTTPONLY COOKIE</span>
          </div>
          <span className="uppercase text-[#9a9ca8]">ARGON2ID</span>
        </div>
      </div>
    </div>
  );
};
