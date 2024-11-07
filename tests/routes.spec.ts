// __tests__/registerV4Routes.test.ts

import { Hono } from "hono";
import { Context } from "hono";
import request from "supertest";
import { registerV4Routes } from "../path/to/your/registerV4Routes"; // Update the path accordingly
import PasskeyRepository from "../path/to/your/repository/PasskeyRepository"; // Update the path accordingly
import {
  generateAuthenticationOptions,
  generateRegistrationOptions,
  verifyAuthenticationResponse,
  verifyRegistrationResponse,
} from "@simplewebauthn/server";

// Mock @simplewebauthn/server
jest.mock("@simplewebauthn/server", () => ({
  generateAuthenticationOptions: jest.fn(),
  generateRegistrationOptions: jest.fn(),
  verifyAuthenticationResponse: jest.fn(),
  verifyRegistrationResponse: jest.fn(),
}));

// Mock PasskeyRepository
jest.mock("../path/to/your/repository/PasskeyRepository"); // Update the path accordingly

describe("Passkey Storage Server", () => {
  let app: Hono;
  let passkeyRepo: jest.Mocked<PasskeyRepository>;
  const CHALLENGE_TTL = 300; // Example TTL

  beforeEach(() => {
    // Clear all mocks before each test
    jest.clearAllMocks();

    // Instantiate the mocked PasskeyRepository
    passkeyRepo = new PasskeyRepository() as jest.Mocked<PasskeyRepository>;

    // Setup default mock implementations
    passkeyRepo.set.mockResolvedValue(true);
    passkeyRepo.get.mockResolvedValue(true as any);
    passkeyRepo.delete.mockResolvedValue(true);
    passkeyRepo.createUser.mockResolvedValue(true);
    passkeyRepo.createCredential.mockResolvedValue(true);
    passkeyRepo.getCredentialById.mockResolvedValue({
      credentialId: "credential-id",
      publicKey: "public-key",
      counter: 0,
      pubKey: "pubKey",
    } as any);
    passkeyRepo.updateCredentialCounter.mockResolvedValue(true);

    // Create a new Hono app and register routes
    app = new Hono();
    registerV4Routes(app, passkeyRepo, CHALLENGE_TTL);
  });

  describe("POST /api/v4/register/options", () => {
    it("should generate registration options and return them with userId", async () => {
      // Mock the generateRegistrationOptions response
      (generateRegistrationOptions as jest.Mock).mockResolvedValue({
        challenge: "fake-challenge",
        rp: { name: "example.com", id: "example.com" },
        user: { id: "user-id", name: "testuser", displayName: "Test User" },
        pubKeyCredParams: [],
        authenticatorSelection: {},
        attestation: "direct",
      });

      const response = await request(app.fetch)
        .post("/api/v4/register/options")
        .send({ username: "testuser" })
        .set("Origin", "https://example.com");

      expect(response.status).toBe(200);
      expect(response.body).toHaveProperty("options");
      expect(response.body).toHaveProperty("userId");
      expect(generateRegistrationOptions).toHaveBeenCalledWith({
        rpName: "example.com",
        rpID: "example.com",
        userID: expect.any(String),
        userName: "testuser",
        userDisplayName: "testuser",
        authenticatorSelection: {
          residentKey: "required",
          userVerification: "required",
        },
      });
      expect(passkeyRepo.set).toHaveBeenCalledWith(
        ["challenges", "example.com", "fake-challenge"],
        true,
        { expireIn: CHALLENGE_TTL }
      );
    });

    it("should return 400 if origin header is missing", async () => {
      const response = await request(app.fetch)
        .post("/api/v4/register/options")
        .send({ username: "testuser" });

      expect(response.status).toBe(400);
      expect(response.text).toBe("Origin header is missing");
    });
  });

  describe("POST /api/v4/register/verify", () => {
    it("should verify registration response and create user and credential", async () => {
      // Mock input data
      const mockUserId = "user-id";
      const mockUsername = "testuser";
      const mockCredential: any = {
        response: {
          clientDataJSON: Buffer.from(
            JSON.stringify({
              type: "webauthn.create",
              challenge: "fake-challenge",
              origin: "https://example.com",
            })
          ).toString("base64"),
          publicKey: "public-key",
        },
      };
      const mockCredResponse = {
        ...mockCredential,
      };

      // Mock passkeyRepo.get to return a valid challenge
      passkeyRepo.get.mockResolvedValue(true as any);

      // Mock verifyRegistrationResponse
      (verifyRegistrationResponse as jest.Mock).mockResolvedValue({
        verified: true,
        registrationInfo: {
          credentialID: new Uint8Array([1, 2, 3]),
          credentialPublicKey: new Uint8Array([4, 5, 6]),
          counter: 0,
        },
      });

      const response = await request(app.fetch)
        .post("/api/v4/register/verify")
        .send({
          userId: mockUserId,
          username: mockUsername,
          cred: mockCredResponse,
        })
        .set("Origin", "https://example.com");

      expect(response.status).toBe(200);
      expect(verifyRegistrationResponse).toHaveBeenCalled();
      expect(passkeyRepo.delete).toHaveBeenCalledWith([
        "challenges",
        "example.com",
        "fake-challenge",
      ]);
      expect(passkeyRepo.createUser).toHaveBeenCalledWith({
        userId: mockUserId,
        username: mockUsername,
        projectId: null,
      });
      expect(passkeyRepo.createCredential).toHaveBeenCalledWith({
        credentialId: expect.any(String),
        userId: mockUserId,
        credentialPublicKey: expect.any(String),
        counter: 0,
        publicKey: "public-key",
      });
    });

    it("should return 400 if origin header is missing", async () => {
      const response = await request(app.fetch)
        .post("/api/v4/register/verify")
        .send({
          userId: "user-id",
          username: "testuser",
          cred: {},
        });

      expect(response.status).toBe(400);
      expect(response.text).toBe("Origin header is missing");
    });

    it("should return 401 if userId is missing", async () => {
      const response = await request(app.fetch)
        .post("/api/v4/register/verify")
        .send({
          username: "testuser",
          cred: {},
        })
        .set("Origin", "https://example.com");

      expect(response.status).toBe(401);
      expect(response.text).toBe("UserId Not Found");
    });

    it("should return 400 for invalid challenge", async () => {
      // Mock input data
      const mockUserId = "user-id";
      const mockUsername = "testuser";
      const mockCredResponse = {
        response: {
          clientDataJSON: Buffer.from(
            JSON.stringify({
              type: "webauthn.create",
              challenge: "invalid-challenge",
              origin: "https://example.com",
            })
          ).toString("base64"),
          publicKey: "public-key",
        },
      };

      // Mock passkeyRepo.get to return undefined (invalid challenge)
      passkeyRepo.get.mockResolvedValue(undefined);

      const response = await request(app.fetch)
        .post("/api/v4/register/verify")
        .send({
          userId: mockUserId,
          username: mockUsername,
          cred: mockCredResponse,
        })
        .set("Origin", "https://example.com");

      expect(response.status).toBe(400);
      expect(response.text).toBe("Invalid challenge");
    });

    it("should return 401 if verification fails", async () => {
      // Mock input data
      const mockUserId = "user-id";
      const mockUsername = "testuser";
      const mockCredential: any = {
        response: {
          clientDataJSON: Buffer.from(
            JSON.stringify({
              type: "webauthn.create",
              challenge: "fake-challenge",
              origin: "https://example.com",
            })
          ).toString("base64"),
          publicKey: "public-key",
        },
      };
      const mockCredResponse = {
        ...mockCredential,
      };

      // Mock passkeyRepo.get to return a valid challenge
      passkeyRepo.get.mockResolvedValue(true as any);

      // Mock verifyRegistrationResponse to fail
      (verifyRegistrationResponse as jest.Mock).mockResolvedValue({
        verified: false,
      });

      const response = await request(app.fetch)
        .post("/api/v4/register/verify")
        .send({
          userId: mockUserId,
          username: mockUsername,
          cred: mockCredResponse,
        })
        .set("Origin", "https://example.com");

      expect(response.status).toBe(401);
      expect(response.text).toBe("Unauthorized");
    });
  });

  describe("POST /api/v4/login/options", () => {
    it("should generate authentication options and return them", async () => {
      // Mock the generateAuthenticationOptions response
      (generateAuthenticationOptions as jest.Mock).mockResolvedValue({
        challenge: "login-fake-challenge",
        allowCredentials: [],
      });

      const response = await request(app.fetch)
        .post("/api/v4/login/options")
        .set("Origin", "https://example.com");

      expect(response.status).toBe(200);
      expect(response.body).toHaveProperty("challenge");
      expect(generateAuthenticationOptions).toHaveBeenCalledWith({
        userVerification: "required",
        rpID: "example.com",
      });
      expect(passkeyRepo.set).toHaveBeenCalledWith(
        ["challenges", "example.com", "login-fake-challenge"],
        true,
        { expireIn: CHALLENGE_TTL }
      );
    });

    it("should return 400 if origin header is missing", async () => {
      const response = await request(app.fetch).post("/api/v4/login/options");

      expect(response.status).toBe(400);
      expect(response.text).toBe("Origin header is missing");
    });
  });

  describe("POST /api/v4/login/verify", () => {
    it("should verify authentication response and update credential counter", async () => {
      // Mock input data
      const mockCredResponse = {
        response: {
          clientDataJSON: Buffer.from(
            JSON.stringify({
              type: "webauthn.get",
              challenge: "login-fake-challenge",
              origin: "https://example.com",
            })
          ).toString("base64"),
          userHandle: "user-id",
        },
        id: "credential-id",
      };

      // Mock passkeyRepo.get to return a valid challenge
      passkeyRepo.get.mockResolvedValue(true as any);

      // Mock passkeyRepo.getCredentialById
      passkeyRepo.getCredentialById.mockResolvedValue({
        credentialId: "credential-id",
        publicKey: "public-key",
        counter: 0,
        pubKey: "pubKey",
      } as any);

      // Mock verifyAuthenticationResponse
      (verifyAuthenticationResponse as jest.Mock).mockResolvedValue({
        verified: true,
        authenticationInfo: {
          newCounter: 1,
        },
      });

      const response = await request(app.fetch)
        .post("/api/v4/login/verify")
        .send({
          cred: mockCredResponse,
        })
        .set("Origin", "https://example.com");

      expect(response.status).toBe(200);
      expect(verifyAuthenticationResponse).toHaveBeenCalled();
      expect(passkeyRepo.delete).toHaveBeenCalledWith([
        "challenges",
        "example.com",
        "login-fake-challenge",
      ]);
      expect(passkeyRepo.updateCredentialCounter).toHaveBeenCalledWith(
        "credential-id",
        1
      );
      expect(response.body).toHaveProperty("verification");
      expect(response.body).toHaveProperty("pubkey", "pubKey");
      expect(response.body).toHaveProperty("userId", "user-id");
    });

    it("should return 400 if origin header is missing", async () => {
      const response = await request(app.fetch)
        .post("/api/v4/login/verify")
        .send({
          cred: {},
        });

      expect(response.status).toBe(400);
      expect(response.text).toBe("Origin header is missing");
    });

    it("should return 401 if userHandle is missing", async () => {
      const response = await request(app.fetch)
        .post("/api/v4/login/verify")
        .send({
          cred: {
            response: {
              clientDataJSON: Buffer.from(
                JSON.stringify({
                  type: "webauthn.get",
                  challenge: "fake-challenge",
                  origin: "https://example.com",
                })
              ).toString("base64"),
              userHandle: null,
            },
            id: "credential-id",
          },
        })
        .set("Origin", "https://example.com");

      expect(response.status).toBe(401);
      expect(response.body).toHaveProperty("error", "UserId Not Found");
    });

    it("should return 401 if credential is not found", async () => {
      passkeyRepo.getCredentialById.mockResolvedValue(undefined);

      const response = await request(app.fetch)
        .post("/api/v4/login/verify")
        .send({
          cred: {
            response: {
              clientDataJSON: Buffer.from(
                JSON.stringify({
                  type: "webauthn.get",
                  challenge: "fake-challenge",
                  origin: "https://example.com",
                })
              ).toString("base64"),
              userHandle: "user-id",
            },
            id: "credential-id",
          },
        })
        .set("Origin", "https://example.com");

      expect(response.status).toBe(401);
      expect(response.body).toHaveProperty("error", "Unauthorized");
    });

    it("should return 400 for invalid challenge", async () => {
      // Mock input data
      const mockCredResponse = {
        response: {
          clientDataJSON: Buffer.from(
            JSON.stringify({
              type: "webauthn.get",
              challenge: "invalid-challenge",
              origin: "https://example.com",
            })
          ).toString("base64"),
          userHandle: "user-id",
        },
        id: "credential-id",
      };

      // Mock passkeyRepo.get to return undefined (invalid challenge)
      passkeyRepo.get.mockResolvedValue(undefined);

      const response = await request(app.fetch)
        .post("/api/v4/login/verify")
        .send({
          cred: mockCredResponse,
        })
        .set("Origin", "https://example.com");

      expect(response.status).toBe(400);
      expect(response.text).toBe("Invalid challenge");
    });

    it("should return 401 if verification fails", async () => {
      // Mock input data
      const mockCredResponse = {
        response: {
          clientDataJSON: Buffer.from(
            JSON.stringify({
              type: "webauthn.get",
              challenge: "fake-challenge",
              origin: "https://example.com",
            })
          ).toString("base64"),
          userHandle: "user-id",
        },
        id: "credential-id",
      };

      // Mock passkeyRepo.get to return a valid challenge
      passkeyRepo.get.mockResolvedValue(true as any);

      // Mock passkeyRepo.getCredentialById
      passkeyRepo.getCredentialById.mockResolvedValue({
        credentialId: "credential-id",
        publicKey: "public-key",
        counter: 0,
        pubKey: "pubKey",
      } as any);

      // Mock verifyAuthenticationResponse to fail
      (verifyAuthenticationResponse as jest.Mock).mockResolvedValue({
        verified: false,
      });

      const response = await request(app.fetch)
        .post("/api/v4/login/verify")
        .send({
          cred: mockCredResponse,
        })
        .set("Origin", "https://example.com");

      expect(response.status).toBe(401);
      expect(response.text).toBe("Unauthorized");
    });

    it("should return 500 for unexpected errors", async () => {
      // Simulate an error in the verification process
      (verifyAuthenticationResponse as jest.Mock).mockImplementation(() => {
        throw new Error("Unexpected error");
      });

      const response = await request(app.fetch)
        .post("/api/v4/login/verify")
        .send({
          cred: {},
        })
        .set("Origin", "https://example.com");

      expect(response.status).toBe(500);
      expect(response.text).toBe("Internal Server Error");
    });
  });
});
