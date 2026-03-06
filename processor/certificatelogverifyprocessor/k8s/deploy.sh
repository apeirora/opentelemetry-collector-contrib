#!/bin/bash
set -e

echo "========================================"
echo "Deploy Certificate Log Verify Processor"
echo "========================================"
echo ""

NAMESPACE="otel-demo"

echo "Step 1: Creating namespace..."
kubectl apply -f namespace.yaml

echo ""
echo "Step 2: Creating RBAC resources..."
kubectl apply -f rbac.yaml

echo ""
echo "Step 3: Creating ConfigMap..."
kubectl apply -f configmap.yaml

echo ""
echo "Step 4: Creating Deployment..."
kubectl apply -f deployment.yaml

echo ""
echo "Step 5: Creating Service..."
kubectl apply -f service.yaml

echo ""
echo "Step 6: Waiting for deployment to be ready..."
kubectl wait --for=condition=available --timeout=300s deployment/otelcol-certificatelogverify -n $NAMESPACE

if [ $? -eq 0 ]; then
    echo ""
    echo "========================================"
    echo "SUCCESS! Deployment is ready"
    echo "========================================"
    echo ""
    echo "Pods:"
    kubectl get pods -n $NAMESPACE -l app=otelcol-certificatelogverify
    echo ""
    echo "Service:"
    kubectl get svc -n $NAMESPACE otelcol-certificatelogverify
    echo ""
    echo "To view logs:"
    echo "  kubectl logs -n $NAMESPACE -l app=otelcol-certificatelogverify"
else
    echo ""
    echo "WARNING: Deployment not ready within timeout"
    echo "Checking pod status..."
    kubectl get pods -n $NAMESPACE -l app=otelcol-certificatelogverify
    kubectl describe pod -n $NAMESPACE -l app=otelcol-certificatelogverify | grep -E "Error|Warning" -A 2
fi
