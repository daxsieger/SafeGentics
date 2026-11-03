/**
 * Simulated workspace files across security realms for testing and demonstration.
 */

export interface WorkspaceFile {
  path: string;
  name: string;
  language: string;
  expectedRealmId: string;
  content: string;
}

export const SAMPLE_WORKSPACE_FILES: WorkspaceFile[] = [
  {
    path: '.env.production',
    name: '.env.production',
    language: 'ini',
    expectedRealmId: 'secrets',
    content: `# Production Environment Secrets & API Tokens
DATABASE_URL="postgresql://db_admin:SuperSecretPass987@prod-db.internal:5432/orders"
OPENAI_API_KEY="sk-proj-prod99948271847192847192"
JWT_SIGNING_SECRET="9f82c4e1a0b3d8e5f2a1b9c4d7e8f0a3"
STRIPE_LIVE_KEY="sk_live_51MzAbcDef123456789SecretToken"
AWS_SECRET_ACCESS_KEY="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"`,
  },
  {
    path: 'certs/private.key',
    name: 'private.key',
    language: 'plaintext',
    expectedRealmId: 'secrets',
    content: `-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA0Y3J1g7Hk9X7k3P6v0m7t1l4q5r8s9t0u1v2w3x4y5z6a7b8
c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0
e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2
-----END RSA PRIVATE KEY-----`,
  },
  {
    path: 'docker-compose.yml',
    name: 'docker-compose.yml',
    language: 'yaml',
    expectedRealmId: 'infrastructure',
    content: `version: '3.8'

services:
  api:
    build: .
    ports:
      - "3000:3000"
    environment:
      - NODE_ENV=production
    depends_on:
      - postgres
      - redis

  postgres:
    image: postgres:16-alpine
    environment:
      POSTGRES_DB: main_app
      POSTGRES_USER: app_user
    volumes:
      - pgdata:/var/lib/postgresql/data

volumes:
  pgdata:`,
  },
  {
    path: 'infra/terraform/main.tf',
    name: 'main.tf',
    language: 'hcl',
    expectedRealmId: 'infrastructure',
    content: `terraform {
  required_version = ">= 1.5.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

resource "aws_db_instance" "production_db" {
  allocated_storage    = 100
  storage_type         = "gp3"
  engine               = "postgres"
  engine_version       = "16.1"
  instance_class       = "db.r6g.xlarge"
  multi_az             = true
  publicly_accessible  = false
}`,
  },
  {
    path: 'src/domain/payment.ts',
    name: 'payment.ts',
    language: 'typescript',
    expectedRealmId: 'business_logic',
    content: `/**
 * Payment Domain Logic & Invariant Validation
 */

export interface PaymentRequest {
  orderId: string;
  amountCents: number;
  currency: string;
  idempotencyKey: string;
}

export interface PaymentReceipt {
  transactionId: string;
  status: 'COMPLETED' | 'FAILED';
  settledAt: Date;
}

export class PaymentProcessor {
  public validateInvariants(request: PaymentRequest): boolean {
    if (request.amountCents <= 0) {
      throw new Error("Payment amount must be strictly positive");
    }
    if (!['USD', 'EUR', 'GBP'].includes(request.currency)) {
      throw new Error("Unsupported settlement currency: " + request.currency);
    }
    return true;
  }

  public calculateFee(amountCents: number): number {
    // 2.9% + 30 cents standard fee schedule
    return Math.round(amountCents * 0.029) + 30;
  }
}`,
  },
  {
    path: 'src/controllers/checkout.ts',
    name: 'checkout.ts',
    language: 'typescript',
    expectedRealmId: 'presentation_and_api',
    content: `import { PaymentProcessor, PaymentRequest } from '../domain/payment.ts';

export async function handleCheckout(req: { body: PaymentRequest }, res: { json: (d: unknown) => void }) {
  const processor = new PaymentProcessor();
  processor.validateInvariants(req.body);
  
  const fee = processor.calculateFee(req.body.amountCents);
  res.json({
    status: 'READY_TO_CHARGE',
    amount: req.body.amountCents,
    feeCents: fee,
  });
}`,
  },
  {
    path: 'tests/payment.spec.ts',
    name: 'payment.spec.ts',
    language: 'typescript',
    expectedRealmId: 'test_sandbox',
    content: `import { describe, it, expect } from 'vitest';
import { PaymentProcessor } from '../src/domain/payment.ts';

describe('PaymentProcessor Domain Invariants', () => {
  it('correctly calculates interchange transaction fees', () => {
    const processor = new PaymentProcessor();
    const fee = processor.calculateFee(10000); // $100.00
    expect(fee).toBe(320); // $3.20
  });

  it('rejects negative or zero payment amounts', () => {
    const processor = new PaymentProcessor();
    expect(() => {
      processor.validateInvariants({
        orderId: 'ORD-1',
        amountCents: -50,
        currency: 'USD',
        idempotencyKey: 'k-1',
      });
    }).toThrow(/strictly positive/);
  });
});`,
  },
];
