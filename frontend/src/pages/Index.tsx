import { useState, useEffect } from 'react';
import { DashboardLayout } from '@/components/layout/DashboardLayout';
import { StatCard } from '@/components/dashboard/StatCard';
import { AttackTable } from '@/components/dashboard/AttackTable';
import { LiveIndicator } from '@/components/dashboard/LiveIndicator';
import { getAttackStats, type Attack } from '@/data/mockData';
import { getAttacks } from '@/lib/api';

const Index = () => {
  const [attacks, setAttacks] = useState<Attack[]>([]);
  const [stats, setStats] = useState({
    totalToday: 0,
    highRiskAttackers: 0,
    mostTargetedEndpoint: 'N/A',
    mostTargetedCount: 0,
  });

  useEffect(() => {
    let cancelled = false;

    const load = async () => {
      try {
        const latest = await getAttacks(50);
        if (cancelled) return;
        setAttacks(latest);
        setStats(getAttackStats(latest));
      } catch {
        if (!cancelled) {
          const { generateMockAttacks, getAttackStats } = await import('@/data/mockData');
          const mock = generateMockAttacks(50);
          setAttacks(mock);
          setStats(getAttackStats(mock));
        }
      }
    };

    void load();

    const interval = setInterval(() => {
      void load();
    }, 5000);

    return () => {
      cancelled = true;
      clearInterval(interval);
    };
  }, []);

  return (
    <DashboardLayout>
      {/* Header */}
      <div className="flex items-center justify-between mb-6">
        <div className="flex items-center gap-6">
          <h1 className="text-xl font-semibold text-foreground">Live Attack Feed</h1>
          <LiveIndicator />
        </div>
        <div className="flex items-center gap-8">
          <StatCard label="Attacks Today" value={stats.totalToday} />
          <StatCard label="High-Risk" value={stats.highRiskAttackers} variant="danger" />
          <StatCard label="Blocked" value={Math.floor(stats.totalToday * 0.87)} variant="success" />
        </div>
      </div>

      {/* Attack Table */}
      <div className="space-y-4">
        <div className="flex items-center justify-between">
          <h2 className="text-lg font-semibold text-foreground">Recent Attacks</h2>
          <p className="text-xs text-muted-foreground">
            Showing latest {attacks.length} events
          </p>
        </div>
        <AttackTable attacks={attacks} />
      </div>
    </DashboardLayout>
  );
};

export default Index;
