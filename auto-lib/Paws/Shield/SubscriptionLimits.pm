# Generated by default/object.tt
package Paws::Shield::SubscriptionLimits;
  use Moose;
  has ProtectionGroupLimits => (is => 'ro', isa => 'Paws::Shield::ProtectionGroupLimits', required => 1);
  has ProtectionLimits => (is => 'ro', isa => 'Paws::Shield::ProtectionLimits', required => 1);

1;

### main pod documentation begin ###

=head1 NAME

Paws::Shield::SubscriptionLimits

=head1 USAGE

This class represents one of two things:

=head3 Arguments in a call to a service

Use the attributes of this class as arguments to methods. You shouldn't make instances of this class. 
Each attribute should be used as a named argument in the calls that expect this type of object.

As an example, if Att1 is expected to be a Paws::Shield::SubscriptionLimits object:

  $service_obj->Method(Att1 => { ProtectionGroupLimits => $value, ..., ProtectionLimits => $value  });

=head3 Results returned from an API call

Use accessors for each attribute. If Att1 is expected to be an Paws::Shield::SubscriptionLimits object:

  $result = $service_obj->Method(...);
  $result->Att1->ProtectionGroupLimits

=head1 DESCRIPTION

Limits settings for your subscription.

=head1 ATTRIBUTES


=head2 B<REQUIRED> ProtectionGroupLimits => L<Paws::Shield::ProtectionGroupLimits>

Limits settings on protection groups for your subscription.


=head2 B<REQUIRED> ProtectionLimits => L<Paws::Shield::ProtectionLimits>

Limits settings on protections for your subscription.



=head1 SEE ALSO

This class forms part of L<Paws>, describing an object used in L<Paws::Shield>

=head1 BUGS and CONTRIBUTIONS

The source code is located here: L<https://github.com/pplu/aws-sdk-perl>

Please report bugs to: L<https://github.com/pplu/aws-sdk-perl/issues>

=cut

